use fat_core::kernel_system::{
    evaluate_kernel_promotion, ArchitectureContract, ArtifactFile, FixtureOutcome,
    KernelArtifactBundleManifest, KernelBuildRecipe, KernelBuilderIdentity, KernelClass,
    KernelFixtureResult, KernelPromotionDecision, KernelPromotionEvidence, KernelPromotionPolicy,
    KernelPromotionRecord, KernelSourceLock, PromotionExperimentEvidence, SupportTier,
};
use std::fs;
use std::path::{Path, PathBuf};

const DIGEST_A: &str = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
const DIGEST_B: &str = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb";

fn source_lock() -> KernelSourceLock {
    KernelSourceLock {
        schema_version: "1.0".into(),
        id: String::new(),
        project: "Linux".into(),
        release: "6.18.45".into(),
        archive_url: "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.18.45.tar.xz".into(),
        archive_digest: DIGEST_A.into(),
        signature_url: Some(
            "https://cdn.kernel.org/pub/linux/kernel/v6.x/linux-6.18.45.tar.sign".into(),
        ),
        checksums_url: Some("https://cdn.kernel.org/pub/linux/kernel/v6.x/sha256sums.asc".into()),
        license: "GPL-2.0-only".into(),
    }
    .seal()
    .expect("valid source lock")
}

fn recipe() -> KernelBuildRecipe {
    KernelBuildRecipe {
        schema_version: "1.0".into(),
        id: String::new(),
        class: KernelClass::Mips32O32LeR1Page4k,
        source_lock_id: source_lock().id,
        builder_id: "kbi-0123456789abcdef".into(),
        architecture: ArchitectureContract {
            isa_family: "mips32".into(),
            endianness: "little".into(),
            userspace_abi: "o32".into(),
            isa_floor: "mips32r1".into(),
            page_size: 4096,
        },
        cross_compile: "mipsel-linux-gnu-".into(),
        base_defconfig: "malta_defconfig".into(),
        ordered_fragments: vec![
            "config/common.config".into(),
            "config/mips32le.config".into(),
        ],
        output_image: "vmlinux".into(),
        machine_profile_ids: vec!["mch-qemu-malta-v1".into()],
        support_tier: SupportTier::Experimental,
    }
    .seal()
    .expect("valid recipe")
}

fn bundle() -> KernelArtifactBundleManifest {
    let recipe = recipe();
    KernelArtifactBundleManifest {
        schema_version: "1.0".into(),
        id: String::new(),
        recipe_id: recipe.id,
        class: recipe.class,
        support_tier: SupportTier::Experimental,
        source_lock_id: recipe.source_lock_id,
        builder_id: recipe.builder_id,
        kernel_image: ArtifactFile {
            path: "vmlinux".into(),
            digest: DIGEST_A.into(),
            role: "kernel-image".into(),
        },
        final_config: ArtifactFile {
            path: "config.final".into(),
            digest: DIGEST_B.into(),
            role: "kernel-config".into(),
        },
        build_log: ArtifactFile {
            path: "build.log".into(),
            digest: DIGEST_A.into(),
            role: "build-log".into(),
        },
        declared_files: vec![],
        attribution: vec![],
        recipe_reproducible: true,
        bit_reproducible: false,
    }
    .seal()
    .expect("valid bundle")
}

#[test]
fn strict_source_lock_rejects_unknown_fields() {
    let value = serde_json::json!({
        "schema_version": "1.0",
        "id": "",
        "project": "Linux",
        "release": "6.18.45",
        "archive_url": "https://cdn.kernel.org/linux.tar.xz",
        "archive_digest": DIGEST_A,
        "license": "GPL-2.0-only",
        "silent_default": true
    });

    let error = serde_json::from_value::<KernelSourceLock>(value)
        .expect_err("unknown fields must be refused");
    assert!(error.to_string().contains("unknown field"));
}

#[test]
fn sealing_is_content_addressed_and_stable() {
    let first = recipe();
    let second = recipe();

    assert_eq!(first.id, second.id);
    assert!(first.id.starts_with("krc-"));

    let mut changed = second;
    changed.output_image = "vmlinuz".into();
    changed.id.clear();
    let changed = changed.seal().expect("changed recipe remains valid");
    assert_ne!(first.id, changed.id);
}

#[test]
fn recipe_refuses_path_traversal_and_class_contract_mismatch() {
    let mut invalid = recipe();
    invalid.id.clear();
    invalid.ordered_fragments = vec!["../borrowed.config".into()];
    invalid.architecture.endianness = "big".into();

    let errors = invalid.seal().expect_err("invalid recipe must fail");
    assert!(errors.iter().any(|error| error.code == "unsafe-path"));
    assert!(errors
        .iter()
        .any(|error| error.code == "class-contract-mismatch"));
}

#[test]
fn artifact_bundle_requires_attribution_for_redistributed_input() {
    let mut invalid = bundle();
    invalid.id.clear();
    invalid.declared_files.push(ArtifactFile {
        path: "borrowed/vendor.patch".into(),
        digest: DIGEST_B.into(),
        role: "third-party-input".into(),
    });

    let errors = invalid
        .seal()
        .expect_err("third-party material requires attribution");
    assert!(errors
        .iter()
        .any(|error| error.code == "attribution-required"));
}

#[test]
fn promotion_refuses_success_without_fixture_cleanup_and_required_predicates() {
    let bundle = bundle();
    let fixture = KernelFixtureResult {
        schema_version: "1.0".into(),
        id: String::new(),
        bundle_id: bundle.id.clone(),
        kernel_digest: bundle.kernel_image.digest.clone(),
        machine_profile_id: "mch-qemu-malta-v1".into(),
        qemu_binary_digest: DIGEST_B.into(),
        cpu: "24Kf".into(),
        process_id: 1,
        predicted_outcome: FixtureOutcome::UserspaceReached,
        observed_outcome: FixtureOutcome::KernelBooted,
        serial_log_digest: DIGEST_A.into(),
        cleanup_passed: false,
    }
    .seal()
    .expect("a failed fixture is still a valid observation");

    let promotion = KernelPromotionRecord {
        schema_version: "1.0".into(),
        id: String::new(),
        class: KernelClass::Mips32O32LeR1Page4k,
        bundle_id: bundle.id,
        decision: KernelPromotionDecision::Promoted,
        policy_id: "kernel-promotion-v1".into(),
        fixture_result_ids: vec![fixture.id],
        counted_experiment_ids: vec![],
        satisfied_predicates: vec!["artifact-integrity".into()],
        missing_predicates: vec!["fixture-cleanup".into(), "holdout-breadth".into()],
        reasons: vec!["fixture did not reach userspace".into()],
    };

    let errors = promotion
        .seal()
        .expect_err("promotion cannot coexist with missing predicates");
    assert!(errors
        .iter()
        .any(|error| error.code == "promotion-evidence-incomplete"));
}

#[test]
fn not_promoted_is_a_valid_evidence_bounded_decision() {
    let bundle = bundle();
    let record = KernelPromotionRecord {
        schema_version: "1.0".into(),
        id: String::new(),
        class: KernelClass::Mips32O32LeR1Page4k,
        bundle_id: bundle.id,
        decision: KernelPromotionDecision::NotPromoted,
        policy_id: "kernel-promotion-v1".into(),
        fixture_result_ids: vec![],
        counted_experiment_ids: vec![],
        satisfied_predicates: vec!["artifact-integrity".into()],
        missing_predicates: vec!["deterministic-fixture".into(), "holdout-breadth".into()],
        reasons: vec!["no boot evidence has been collected".into()],
    }
    .seal()
    .expect("not-promoted records preserve incomplete evidence");

    assert!(record.id.starts_with("kpr-"));
    assert_eq!(record.decision, KernelPromotionDecision::NotPromoted);
}

#[test]
fn checked_in_source_and_builder_records_are_pinned_and_valid() {
    let root = repository_root();
    let source: KernelSourceLock =
        load_json(&root.join("profiles/kernels/source-locks/linux-6.18.45.json"));
    let builder: KernelBuilderIdentity =
        load_json(&root.join("profiles/kernels/builders/debian-13-cross.json"));

    source.validate().expect("checked-in source lock");
    builder.validate().expect("checked-in builder identity");
    assert_eq!(
        source.archive_digest,
        "sha256:30fa4a56579ca614ac125a12614f7f6466f87ab1278aef7b951dd74156deab33"
    );
    assert_eq!(
        builder.manifest_digest,
        "sha256:32067fcfd49030bab6fbe36633a789ffd97ab19a1fbe00b616a927d499612ff6"
    );
    assert_eq!(
        builder.base_manifest_digest,
        "sha256:38a76d01668772e381ad2826d876627c89e7133e2f8a0f5d567306798b0f2a16"
    );
    assert!(builder.image.contains("@sha256:"));
}

#[test]
fn checked_in_tier_a_recipes_are_closed_and_reference_existing_fragments() {
    let root = repository_root();
    let source: KernelSourceLock =
        load_json(&root.join("profiles/kernels/source-locks/linux-6.18.45.json"));
    let builder: KernelBuilderIdentity =
        load_json(&root.join("profiles/kernels/builders/debian-13-cross.json"));
    let expected = [
        (
            "linux-mips32-o32-le-r1-4k.json",
            KernelClass::Mips32O32LeR1Page4k,
        ),
        (
            "linux-mips32-o32-be-r1-4k.json",
            KernelClass::Mips32O32BeR1Page4k,
        ),
        (
            "linux-arm32-eabi-le-v7-4k.json",
            KernelClass::Arm32EabiLeV7Page4k,
        ),
    ];

    for (name, class) in expected {
        let recipe: KernelBuildRecipe =
            load_json(&root.join("profiles/kernels/recipes").join(name));
        recipe.validate().expect("checked-in recipe");
        assert_eq!(recipe.class, class);
        assert_eq!(recipe.source_lock_id, source.id);
        assert_eq!(recipe.builder_id, builder.id);
        for fragment in &recipe.ordered_fragments {
            assert!(
                root.join("profiles/kernels").join(fragment).is_file(),
                "missing fragment {fragment}"
            );
        }
    }
}

#[test]
fn checked_in_attribution_names_upstream_and_prior_art_without_claiming_imports() {
    let attribution = fs::read_to_string(repository_root().join("profiles/kernels/ATTRIBUTION.md"))
        .expect("kernel attribution");

    for required in ["Linux", "kernel.org", "GPL-2.0", "FirmAE", "Firmadyne"] {
        assert!(
            attribution.contains(required),
            "missing attribution: {required}"
        );
    }
    assert!(attribution.contains("No FirmAE or Firmadyne kernel configuration is copied"));
}

fn repository_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .expect("repository root")
}

fn load_json<T: serde::de::DeserializeOwned>(path: &Path) -> T {
    let bytes = fs::read(path).unwrap_or_else(|error| panic!("read {}: {error}", path.display()));
    serde_json::from_slice(&bytes)
        .unwrap_or_else(|error| panic!("parse {}: {error}", path.display()))
}

#[test]
fn promotion_evaluator_distinguishes_promoted_not_promoted_and_indeterminate() {
    let bundle = bundle();
    let fixture = |machine: &str| {
        KernelFixtureResult {
            schema_version: "1.0".into(),
            id: String::new(),
            bundle_id: bundle.id.clone(),
            kernel_digest: bundle.kernel_image.digest.clone(),
            machine_profile_id: machine.into(),
            qemu_binary_digest: DIGEST_B.into(),
            cpu: "24Kf".into(),
            process_id: 1,
            predicted_outcome: FixtureOutcome::UserspaceReached,
            observed_outcome: FixtureOutcome::UserspaceReached,
            serial_log_digest: DIGEST_A.into(),
            cleanup_passed: true,
        }
        .seal()
        .expect("fixture record")
    };
    let experiment =
        |id: &str, vendor: &str, family_id: &str, corpus_role: &str| PromotionExperimentEvidence {
            experiment_id: id.into(),
            record_digest: DIGEST_A.into(),
            target_id: format!("target-{id}"),
            vendor: vendor.into(),
            family_id: family_id.into(),
            corpus_role: corpus_role.into(),
            finalized: true,
            available: true,
            bindings_match: true,
            cleanup_passed: true,
            proof_stage: 3,
            baseline_proof_stage: 3,
            highest_semantic_risk: "low".into(),
        };
    let policy = KernelPromotionPolicy {
        schema_version: "1.0".into(),
        id: "kernel-promotion-v1".into(),
        minimum_distinct_vendors: 2,
        minimum_distinct_targets: 2,
        minimum_distinct_families: 2,
        minimum_fixture_machines: 2,
        require_holdout: true,
        maximum_semantic_risk: "medium".into(),
    };
    let complete = KernelPromotionEvidence {
        class: bundle.class,
        bundle_id: bundle.id.clone(),
        artifact_verified: true,
        fixtures: vec![fixture("mch-r1"), fixture("mch-r2")],
        experiments: vec![
            experiment("exp-demo-camera", "Demo Camera", "camera", "development"),
            experiment("exp-dlink", "D-Link", "router", "holdout"),
        ],
    };

    let promoted = evaluate_kernel_promotion(&policy, &complete).expect("promotion evaluation");
    assert_eq!(promoted.decision, KernelPromotionDecision::Promoted);

    let mut insufficient = complete.clone();
    insufficient.experiments.truncate(1);
    let not_promoted =
        evaluate_kernel_promotion(&policy, &insufficient).expect("bounded non-promotion");
    assert_eq!(not_promoted.decision, KernelPromotionDecision::NotPromoted);
    assert!(not_promoted
        .missing_predicates
        .contains(&"vendor-breadth".into()));

    let mut unavailable = complete;
    unavailable.experiments[1].available = false;
    let indeterminate =
        evaluate_kernel_promotion(&policy, &unavailable).expect("indeterminate evaluation");
    assert_eq!(
        indeterminate.decision,
        KernelPromotionDecision::Indeterminate
    );
}

#[test]
fn promotion_evaluator_rejects_forged_fixtures_and_zero_thresholds() {
    let bundle = bundle();
    let mut fixture = KernelFixtureResult {
        schema_version: "1.0".into(),
        id: String::new(),
        bundle_id: bundle.id.clone(),
        kernel_digest: bundle.kernel_image.digest.clone(),
        machine_profile_id: "mch-r1".into(),
        qemu_binary_digest: DIGEST_B.into(),
        cpu: "4Kc".into(),
        process_id: 1,
        predicted_outcome: FixtureOutcome::UserspaceReached,
        observed_outcome: FixtureOutcome::UserspaceReached,
        serial_log_digest: DIGEST_A.into(),
        cleanup_passed: true,
    }
    .seal()
    .expect("fixture");
    fixture.observed_outcome = FixtureOutcome::ServiceReached;

    let policy = KernelPromotionPolicy {
        schema_version: "1.0".into(),
        id: "kernel-promotion-v1".into(),
        minimum_distinct_vendors: 0,
        minimum_distinct_targets: 0,
        minimum_distinct_families: 0,
        minimum_fixture_machines: 0,
        require_holdout: false,
        maximum_semantic_risk: "medium".into(),
    };
    let evidence = KernelPromotionEvidence {
        class: bundle.class,
        bundle_id: bundle.id,
        artifact_verified: true,
        fixtures: vec![fixture],
        experiments: vec![],
    };

    let errors = evaluate_kernel_promotion(&policy, &evidence)
        .expect_err("forged fixture and empty thresholds must fail closed");
    assert!(errors
        .iter()
        .any(|error| error.code == "content-id-mismatch"));
    assert!(errors
        .iter()
        .any(|error| error.code == "promotion-threshold-invalid"));
}
