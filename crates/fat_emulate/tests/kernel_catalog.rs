use fat_core::data_dir::DataResolver;
use fat_emulate::kernel_catalog::{
    load_embedded_kernel_catalog, load_kernel_catalog, load_machine_profile_for_host,
    load_required_machine_profile, select_kernel_profile_with_artifacts,
    select_kernel_profile_with_demotions, KernelProfile,
};
use fat_emulate::target_profile::{build_target_model, TargetProfileRequest};

#[test]
fn embedded_kernel_catalog_prefers_family_specific_profiles_before_generic_fallbacks() {
    let catalog = load_embedded_kernel_catalog().expect("embedded catalog");
    let model = build_target_model(&TargetProfileRequest {
        project_id: "demo".to_string(),
        target_id: "target-demo".to_string(),
        evidence: vec![
            "arch:armel".to_string(),
            "fs:squashfs".to_string(),
            "init:/etc/init.d/rcS".to_string(),
        ],
    });

    let selected =
        select_kernel_profile_with_demotions(&catalog, &model, &[]).expect("selected profile");

    assert_eq!(selected.architecture, "armel");
    assert!(selected.family_hint.starts_with("linux-router-arm"));
}

#[test]
fn embedded_kernel_catalog_can_demote_a_profile_and_fall_back_to_the_next_tier() {
    let catalog = load_embedded_kernel_catalog().expect("embedded catalog");
    let model = build_target_model(&TargetProfileRequest {
        project_id: "demo".to_string(),
        target_id: "target-demo".to_string(),
        evidence: vec![
            "arch:armel".to_string(),
            "fs:squashfs".to_string(),
            "init:/etc/init.d/rcS".to_string(),
        ],
    });
    let preferred =
        select_kernel_profile_with_demotions(&catalog, &model, &[]).expect("preferred profile");

    let fallback = select_kernel_profile_with_demotions(
        &catalog,
        &model,
        std::slice::from_ref(&preferred.profile_id),
    )
    .expect("fallback profile");

    assert_ne!(fallback.profile_id, preferred.profile_id);
    assert!(fallback.tier >= preferred.tier);
}

#[test]
fn kernel_catalog_can_be_loaded_from_an_explicit_runtime_data_root() {
    let temp = tempfile::tempdir().expect("tempdir");
    let catalog_path = temp.path().join("profiles/kernels/catalog.json");
    std::fs::create_dir_all(catalog_path.parent().unwrap()).unwrap();
    std::fs::write(
        &catalog_path,
        r#"[{"profile_id":"external","architecture":"armel","family_hint":"linux-","tier":1,"image_hint":"zImage","support_tier":"external","compatibility_note":"test"}]"#,
    )
    .unwrap();
    let resolver =
        DataResolver::from_paths(Some(temp.path().to_path_buf()), None, None, None, None);

    let catalog = load_kernel_catalog(&resolver).expect("runtime catalog");

    assert_eq!(catalog[0].profile_id, "external");
}

#[test]
fn managed_profile_resolves_its_exact_machine_contract() {
    let mut profile = KernelProfile::new(
        "managed-mipsel",
        "mipsel",
        "linux-",
        0,
        "vmlinux",
        "experimental",
        "test",
    );
    profile.compatibility_class = Some(fat_core::kernel_system::KernelClass::Mips32O32LeR1Page4k);
    profile.required_machine_profile = Some("mch-qemu-11-0-2-malta-r2".into());

    let machine = load_required_machine_profile(&profile)
        .expect("machine lookup")
        .expect("required machine");
    assert_eq!(machine.qemu_version, "11.0.2");
    assert_eq!(machine.machine, "malta");
    assert_eq!(machine.cpu, "24Kf");
    assert!(machine
        .classes
        .contains(&profile.compatibility_class.unwrap()));
}

fn arm_profile_with_validated_set() -> KernelProfile {
    let mut profile = KernelProfile::new(
        "managed-arm",
        "armel",
        "linux-",
        0,
        "zImage",
        "experimental",
        "test",
    );
    profile.compatibility_class = Some(fat_core::kernel_system::KernelClass::Arm32EabiLeV7Page4k);
    profile.required_machine_profile = Some("mch-qemu-11-0-2-virt-armv7".into());
    profile.compatible_machine_profiles = vec![
        "mch-qemu-11-0-2-virt-armv7".into(),
        "mch-qemu-10-2-virt-armv7".into(),
    ];
    profile
}

// The point of the validated set: a host on 10.2 gets the 10.2 profile instead
// of being refused a kernel the fixture matrix already proved works there.
#[test]
fn a_host_running_a_validated_qemu_gets_that_machine_profile() {
    let profile = arm_profile_with_validated_set();

    let machine = load_machine_profile_for_host(&profile, Some("10.2.2"))
        .expect("machine lookup")
        .expect("selected machine");
    assert_eq!(machine.id, "mch-qemu-10-2-virt-armv7");
    assert_eq!(machine.qemu_version, "10.2.2");
    assert_eq!(machine.machine, "virt-10.2");
}

#[test]
fn the_declared_preference_still_wins_when_the_host_matches_it() {
    let profile = arm_profile_with_validated_set();

    let machine = load_machine_profile_for_host(&profile, Some("11.0.2"))
        .expect("machine lookup")
        .expect("selected machine");
    assert_eq!(machine.id, "mch-qemu-11-0-2-virt-armv7");
}

// An unvalidated QEMU must not be quietly served some other profile: fall back
// to the declared preference so the launch-path version check reports the
// specific version the kernel wants.
#[test]
fn an_unvalidated_qemu_falls_back_to_the_declared_preference() {
    let profile = arm_profile_with_validated_set();

    let machine = load_machine_profile_for_host(&profile, Some("9.1.0"))
        .expect("machine lookup")
        .expect("selected machine");
    assert_eq!(machine.id, "mch-qemu-11-0-2-virt-armv7");
}

#[test]
fn an_unknown_host_version_falls_back_to_the_declared_preference() {
    let profile = arm_profile_with_validated_set();

    let machine = load_machine_profile_for_host(&profile, None)
        .expect("machine lookup")
        .expect("selected machine");
    assert_eq!(machine.id, "mch-qemu-11-0-2-virt-armv7");
}

// Without a validated set the behaviour must be exactly what it was before.
#[test]
fn a_profile_without_a_validated_set_resolves_only_its_required_machine() {
    let mut profile = arm_profile_with_validated_set();
    profile.compatible_machine_profiles = Vec::new();

    let machine = load_machine_profile_for_host(&profile, Some("10.2.2"))
        .expect("machine lookup")
        .expect("selected machine");
    assert_eq!(machine.id, "mch-qemu-11-0-2-virt-armv7");
}

// A compatible entry that does not serve the kernel's class is a data error,
// not something to skip past.
#[test]
fn a_validated_set_entry_must_still_declare_the_kernel_class() {
    let mut profile = arm_profile_with_validated_set();
    profile
        .compatible_machine_profiles
        .push("mch-qemu-10-2-malta-r1".into());

    let error =
        load_machine_profile_for_host(&profile, Some("10.2.2")).expect_err("class mismatch");
    assert!(
        error.contains("does not declare kernel class arm32-eabi-le-v7-page4k"),
        "{error}"
    );
}

#[test]
fn managed_profile_rejects_a_machine_that_does_not_declare_its_class() {
    let mut profile = KernelProfile::new(
        "managed-arm",
        "armel",
        "linux-",
        0,
        "zImage",
        "experimental",
        "test",
    );
    profile.compatibility_class = Some(fat_core::kernel_system::KernelClass::Arm32EabiLeV7Page4k);
    profile.required_machine_profile = Some("mch-qemu-11-0-2-malta-r2".into());

    let error = load_required_machine_profile(&profile).expect_err("class mismatch must fail");
    assert!(error.contains("does not declare kernel class arm32-eabi-le-v7-page4k"));
}

#[test]
fn verified_experimental_managed_kernel_requires_explicit_consent() {
    let temp = tempfile::tempdir().expect("store");
    let bundle = install_fixture_bundle(temp.path());
    let model = build_target_model(&TargetProfileRequest {
        project_id: "demo".into(),
        target_id: "target-demo".into(),
        evidence: vec![
            "arch:mipsel".into(),
            "kernel-class:mips32-o32-le-r1-page4k".into(),
        ],
    });
    let catalog = vec![external_profile(), managed_profile(&bundle)];

    let without_consent =
        select_kernel_profile_with_artifacts(&catalog, &model, &[], Some(temp.path()), false)
            .expect("external fallback");
    assert_eq!(without_consent.profile_id, "external-mipsel");

    let with_consent =
        select_kernel_profile_with_artifacts(&catalog, &model, &[], Some(temp.path()), true)
            .expect("managed selection");
    assert_eq!(with_consent.profile_id, "managed-mipsel");
    assert_eq!(
        with_consent.artifact_digest.as_deref(),
        Some(bundle.kernel_image.digest.as_str())
    );
}

#[test]
fn tampered_managed_kernel_falls_back_to_external_profile() {
    let temp = tempfile::tempdir().expect("store");
    let bundle = install_fixture_bundle(temp.path());
    std::fs::write(
        temp.path().join("bundles").join(&bundle.id).join("vmlinux"),
        b"tampered",
    )
    .unwrap();
    let model = build_target_model(&TargetProfileRequest {
        project_id: "demo".into(),
        target_id: "target-demo".into(),
        evidence: vec![
            "arch:mipsel".into(),
            "kernel-class:mips32-o32-le-r1-page4k".into(),
        ],
    });

    let selected = select_kernel_profile_with_artifacts(
        &[external_profile(), managed_profile(&bundle)],
        &model,
        &[],
        Some(temp.path()),
        true,
    )
    .expect("external fallback");

    assert_eq!(selected.profile_id, "external-mipsel");
}

fn external_profile() -> KernelProfile {
    KernelProfile::new(
        "external-mipsel",
        "mipsel",
        "linux-",
        2,
        "vmlinux.mipsel.4",
        "external-required",
        "test fallback",
    )
}

fn managed_profile(
    bundle: &fat_core::kernel_system::KernelArtifactBundleManifest,
) -> KernelProfile {
    let mut profile = KernelProfile::new(
        "managed-mipsel",
        "mipsel",
        "linux-",
        0,
        "vmlinux",
        "experimental",
        "verified test artifact",
    );
    profile.compatibility_class = Some(bundle.class);
    profile.managed_bundle_id = Some(bundle.id.clone());
    profile.artifact_digest = Some(bundle.kernel_image.digest.clone());
    profile.promotion_state = Some("not-promoted".into());
    profile.required_machine_profile = Some("mch-qemu-10-2-malta-r1".into());
    profile
}

fn install_fixture_bundle(
    store_root: &std::path::Path,
) -> fat_core::kernel_system::KernelArtifactBundleManifest {
    use fat_core::kernel_system::{
        ArtifactFile, KernelArtifactBundleManifest, KernelArtifactStore, KernelClass, SupportTier,
    };
    use sha2::{Digest, Sha256};
    let source = tempfile::tempdir().expect("source");
    let artifact = |name: &str, content: &[u8], role: &str| {
        std::fs::write(source.path().join(name), content).unwrap();
        ArtifactFile {
            path: name.into(),
            digest: format!("sha256:{:x}", Sha256::digest(content)),
            role: role.into(),
        }
    };
    let bundle = KernelArtifactBundleManifest {
        schema_version: "1.0".into(),
        id: String::new(),
        recipe_id: "krc-0123456789abcdef".into(),
        class: KernelClass::Mips32O32LeR1Page4k,
        support_tier: SupportTier::Experimental,
        source_lock_id: "ksl-0123456789abcdef".into(),
        builder_id: "kbi-0123456789abcdef".into(),
        kernel_image: artifact("vmlinux", b"kernel", "kernel-image"),
        final_config: artifact("config.final", b"CONFIG_TEST=y\n", "kernel-config"),
        build_log: artifact("build.log", b"ok\n", "build-log"),
        declared_files: vec![],
        attribution: vec![],
        recipe_reproducible: true,
        bit_reproducible: false,
    }
    .seal()
    .unwrap();
    KernelArtifactStore::new(store_root)
        .install(source.path(), &bundle)
        .unwrap();
    bundle
}
