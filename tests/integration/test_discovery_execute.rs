use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use fat_core::discovery::DiscoveryLifecycleStatus;
use fat_core::runtime_store::RuntimeStore;
use fat_query::attempt_generation::generate_attempt_bindings;
use fat_query::attempt_generation::{GenerationStrategy, ParamDomain, ParamKind};
use fat_query::discovery::{BugFamily, TriggerRecipeStep};
use fat_query::discovery_runtime::{
    execute_harness_plan, execute_harness_plan_with_binding, resolve_runtime_attempt,
    resolve_runtime_attempt_with_binding,
};
use fat_query::harnesses::{ArgTemplate, EnvTemplate, HarnessKind, HarnessPlan, InputBinding};
use fat_query::target_lanes::load_target_lane_manifest;

fn plan_with_command(
    build_dir: &Path,
    artifact_dir: &Path,
    command: &[&str],
    kind: HarnessKind,
    family: BugFamily,
) -> HarnessPlan {
    HarnessPlan {
        harness_id: format!("{:?}-{}", kind, family.as_str()),
        kind,
        family,
        lane_id: "lane-1".into(),
        source_root: build_dir.display().to_string(),
        build_dir: build_dir.display().to_string(),
        launcher_command: command.iter().map(|value| value.to_string()).collect(),
        base_command: Vec::new(),
        argv_template: Vec::new(),
        env_template: BTreeMap::new(),
        input_bindings: Vec::new(),
        param_domains: Vec::new(),
        generation_strategy: Default::default(),
        required_env: BTreeMap::from([("FAT_TEST_ENV".into(), "runtime-smoke".into())]),
        timeout_ms: 1_000,
        artifact_dir: artifact_dir.display().to_string(),
        sanitizer_mode: "asan".into(),
        trigger_recipe: vec![TriggerRecipeStep {
            kind: "runtime-smoke".into(),
            detail: "bounded execution".into(),
        }],
        expected_proof_classes: vec!["asan-use-after-free".into()],
        state_hypothesis_id: Some("runtime-smoke::h0".into()),
        forbidden_transition_id: Some("runtime-smoke-transition".into()),
        attempted_transition_summary: Some("runtime-smoke-transition: bounded execution".into()),
        attempt_plan_hash: "attempt-hash-1".into(),
    }
}

#[test]
fn discovery_runtime_executes_plan_and_persists_attempt_record() {
    let dir = tempfile::tempdir().expect("tempdir");
    let build_dir = dir.path().join("build");
    let artifact_dir = dir.path().join("artifacts");
    fs::create_dir_all(&build_dir).expect("create build dir");

    let plan = plan_with_command(
        &build_dir,
        &artifact_dir,
        &[
            "/bin/sh",
            "-lc",
            "printf 'runtime-stdout'; printf 'runtime-stderr' 1>&2",
        ],
        HarnessKind::ReentrancyTeardown,
        BugFamily::LifetimeReentrancy,
    );

    let result = execute_harness_plan(&plan, 0).expect("execute plan");

    assert_eq!(
        result.attempt.lifecycle,
        DiscoveryLifecycleStatus::Completed
    );
    assert_eq!(result.attempt.outcome, None);
    assert_eq!(result.exit_code, Some(0));
    assert_eq!(result.attempt.resolved_argv, plan.launcher_command);
    assert_eq!(
        result
            .attempt
            .resolved_env
            .get("FAT_TEST_ENV")
            .map(String::as_str),
        Some("runtime-smoke")
    );
    assert_eq!(result.attempt.resolved_cwd, build_dir.display().to_string());
    assert_eq!(result.attempt.timeout_ms, 1_000);
    assert_eq!(
        result.attempt.state_hypothesis_id.as_deref(),
        Some("runtime-smoke::h0")
    );
    assert_eq!(
        result.attempt.forbidden_transition_id.as_deref(),
        Some("runtime-smoke-transition")
    );
    assert!(result.stdout.contains("runtime-stdout"), "{result:#?}");
    assert!(result.stderr.contains("runtime-stderr"), "{result:#?}");
    assert!(Path::new(&result.attempt.artifact_root)
        .join("stdout.txt")
        .exists());
    assert!(Path::new(&result.attempt.artifact_root)
        .join("stderr.txt")
        .exists());

    let store_dir = dir.path().join("store");
    let store = RuntimeStore::open(&store_dir).expect("runtime store");
    store
        .write_harness_attempt(&result.attempt)
        .expect("write attempt");
    assert_eq!(
        store
            .read_harness_attempt(&result.attempt.harness_attempt_id)
            .expect("read attempt"),
        result.attempt
    );
}

#[test]
fn discovery_runtime_marks_failed_infra_when_command_cannot_launch() {
    let dir = tempfile::tempdir().expect("tempdir");
    let build_dir = dir.path().join("build");
    let artifact_dir = dir.path().join("artifacts");
    fs::create_dir_all(&build_dir).expect("create build dir");

    let plan = plan_with_command(
        &build_dir,
        &artifact_dir,
        &["/definitely/missing-fat-runtime-binary"],
        HarnessKind::ShapeStride,
        BugFamily::SizeStrideArithmetic,
    );

    let result = execute_harness_plan(&plan, 1).expect("execute plan");

    assert_eq!(
        result.attempt.lifecycle,
        DiscoveryLifecycleStatus::FailedInfra
    );
    assert_eq!(result.attempt.outcome, None);
    assert_eq!(result.exit_code, None);
    assert_eq!(
        result.attempt.resolved_argv,
        vec!["/definitely/missing-fat-runtime-binary".to_string()]
    );
    assert!(
        result.stderr.contains("failed to launch"),
        "{:#?}",
        result.stderr
    );
}

#[test]
fn discovery_runtime_executes_a_synthetic_public_lane_manifest() {
    let temp = tempfile::tempdir().expect("tempdir");
    let build_dir = temp.path().join("build");
    let artifact_dir = temp.path().join("artifacts");
    fs::create_dir_all(&build_dir).expect("build dir");
    let manifest_path = temp.path().join("synthetic-targets.json");
    fs::write(
        &manifest_path,
        serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": "fat-discovery-target-lanes-v1",
            "lanes": [{
                "lane_id": "synthetic-public-lifetime",
                "family_allowlist": ["lifetime-reentrancy"],
                "source_root": build_dir,
                "build_dir": build_dir,
                "binary_or_driver": "/bin/sh",
                "launcher_command": ["/bin/sh", "-lc", "printf synthetic-lane-smoke"],
                "required_env": {"ASAN_OPTIONS": "symbolize=1"},
                "timeout_ms": 1000,
                "artifact_dir": artifact_dir,
                "sanitizer_mode": "asan",
                "proof_class_allowlist": ["guard-trip"],
                "runtime_capabilities": {},
                "preflight_checks": [{
                    "check_id": "synthetic-build-dir",
                    "kind": "path-exists",
                    "target": "build_dir",
                    "detail": "synthetic build directory exists"
                }]
            }]
        }))
        .expect("manifest json"),
    )
    .expect("write manifest");
    let manifest = load_target_lane_manifest(&manifest_path).expect("synthetic lane manifest");
    let lane = manifest
        .resolve_lane("synthetic-public-lifetime")
        .expect("lifetime lane");

    let plan = HarnessPlan {
        harness_id: "synthetic-lane-smoke".into(),
        kind: HarnessKind::ReentrancyTeardown,
        family: BugFamily::LifetimeReentrancy,
        lane_id: lane.lane_id.clone(),
        source_root: lane.source_root.clone(),
        build_dir: lane.build_dir.clone(),
        launcher_command: lane.launcher_command.clone(),
        base_command: Vec::new(),
        argv_template: Vec::new(),
        env_template: BTreeMap::new(),
        input_bindings: Vec::new(),
        param_domains: Vec::new(),
        generation_strategy: Default::default(),
        required_env: lane.required_env.clone(),
        timeout_ms: 1_000,
        artifact_dir: artifact_dir.display().to_string(),
        sanitizer_mode: lane.sanitizer_mode.clone(),
        trigger_recipe: vec![TriggerRecipeStep {
            kind: "synthetic-lane-smoke".into(),
            detail: "bounded execution using a public synthetic lane".into(),
        }],
        expected_proof_classes: vec!["guard-trip".into()],
        state_hypothesis_id: None,
        forbidden_transition_id: None,
        attempted_transition_summary: None,
        attempt_plan_hash: "synthetic-lane-smoke-attempt".into(),
    };

    let result = execute_harness_plan(&plan, 0).expect("execute plan");

    assert_eq!(
        result.attempt.lifecycle,
        DiscoveryLifecycleStatus::Completed
    );
    assert!(
        result.stdout.contains("synthetic-lane-smoke"),
        "{result:#?}"
    );
}

#[test]
fn discovery_runtime_resolves_templated_argv_and_env_from_input_bindings() {
    let dir = tempfile::tempdir().expect("tempdir");
    let build_dir = dir.path().join("build");
    let artifact_dir = dir.path().join("artifacts");
    fs::create_dir_all(&build_dir).expect("create build dir");

    let plan = HarnessPlan {
        harness_id: "templated-run".into(),
        kind: HarnessKind::ShapeStride,
        family: BugFamily::SizeStrideArithmetic,
        lane_id: "real-angle-lane".into(),
        source_root: build_dir.display().to_string(),
        build_dir: build_dir.display().to_string(),
        launcher_command: vec!["/bin/echo".into()],
        base_command: vec!["/bin/echo".into(), "--family".into(), "size".into()],
        argv_template: vec![
            ArgTemplate::Literal {
                value: "--arg-size".into(),
            },
            ArgTemplate::Binding {
                key: "arg_size".into(),
            },
            ArgTemplate::Literal {
                value: "--symbol".into(),
            },
            ArgTemplate::Binding {
                key: "symbol".into(),
            },
        ],
        env_template: BTreeMap::from([(
            "VK_ICD_FILENAMES".into(),
            EnvTemplate::Binding {
                key: "vk_icd".into(),
            },
        )]),
        input_bindings: vec![
            InputBinding {
                key: "arg_size".into(),
                value: "32".into(),
            },
            InputBinding {
                key: "symbol".into(),
                value: "TextureMtl::setPerSliceSubImage".into(),
            },
            InputBinding {
                key: "vk_icd".into(),
                value: "/tmp/swiftshader_icd.json".into(),
            },
        ],
        param_domains: Vec::new(),
        generation_strategy: Default::default(),
        required_env: BTreeMap::from([("ASAN_OPTIONS".into(), "symbolize=1".into())]),
        timeout_ms: 1_500,
        artifact_dir: artifact_dir.display().to_string(),
        sanitizer_mode: "asan".into(),
        trigger_recipe: vec![TriggerRecipeStep {
            kind: "pitch-depth-mismatch".into(),
            detail: "drive a real arg-size mismatch".into(),
        }],
        expected_proof_classes: vec!["asan-heap-buffer-overflow".into()],
        state_hypothesis_id: Some("templated-run::h0".into()),
        forbidden_transition_id: Some("copy-size-exceeds-allocation".into()),
        attempted_transition_summary: Some(
            "copy-size-exceeds-allocation: drive a real arg-size mismatch".into(),
        ),
        attempt_plan_hash: "templated-attempt".into(),
    };

    let resolved = resolve_runtime_attempt(&plan, 2).expect("resolve attempt");

    assert_eq!(
        resolved.argv,
        vec![
            "/bin/echo".to_string(),
            "--family".to_string(),
            "size".to_string(),
            "--arg-size".to_string(),
            "32".to_string(),
            "--symbol".to_string(),
            "TextureMtl::setPerSliceSubImage".to_string(),
        ]
    );
    assert_eq!(
        resolved.env.get("ASAN_OPTIONS").map(String::as_str),
        Some("symbolize=1")
    );
    assert_eq!(
        resolved.env.get("VK_ICD_FILENAMES").map(String::as_str),
        Some("/tmp/swiftshader_icd.json")
    );
    assert_eq!(resolved.cwd, build_dir.display().to_string());
    assert_eq!(resolved.timeout_ms, 1_500);
    let executed = execute_harness_plan(&plan, 2).expect("execute templated plan");
    assert_eq!(
        executed.attempt.state_hypothesis_id.as_deref(),
        Some("templated-run::h0")
    );
    assert_eq!(
        executed.attempt.forbidden_transition_id.as_deref(),
        Some("copy-size-exceeds-allocation")
    );
}

#[test]
fn discovery_runtime_can_surface_binding_compression_when_distinct_bindings_resolve_identically() {
    let dir = tempfile::tempdir().expect("tempdir");
    let build_dir = dir.path().join("build");
    let artifact_dir = dir.path().join("artifacts");
    fs::create_dir_all(&build_dir).expect("create build dir");

    let plan = HarnessPlan {
        harness_id: "compressed-size-run".into(),
        kind: HarnessKind::ShapeStride,
        family: BugFamily::SizeStrideArithmetic,
        lane_id: "compressed-size-lane".into(),
        source_root: build_dir.display().to_string(),
        build_dir: build_dir.display().to_string(),
        launcher_command: vec!["/bin/echo".into()],
        base_command: vec!["/bin/echo".into()],
        argv_template: vec![ArgTemplate::Binding {
            key: "arg_size".into(),
        }],
        env_template: BTreeMap::new(),
        input_bindings: Vec::new(),
        param_domains: Vec::new(),
        generation_strategy: Default::default(),
        required_env: BTreeMap::new(),
        timeout_ms: 1_000,
        artifact_dir: artifact_dir.display().to_string(),
        sanitizer_mode: "asan".into(),
        trigger_recipe: vec![TriggerRecipeStep {
            kind: "pitch-depth-mismatch".into(),
            detail: "compress distinct logical shapes into the same lane-visible scalar".into(),
        }],
        expected_proof_classes: vec!["asan-heap-buffer-overflow".into()],
        state_hypothesis_id: None,
        forbidden_transition_id: None,
        attempted_transition_summary: None,
        attempt_plan_hash: "compressed-size-attempt".into(),
    };

    let binding_a = fat_query::attempt_generation::GeneratedAttemptBinding {
        binding_id: "compressed-size-run::g0".into(),
        inputs: vec![
            InputBinding {
                key: "arg_size".into(),
                value: "64".into(),
            },
            InputBinding {
                key: "width".into(),
                value: "4".into(),
            },
            InputBinding {
                key: "row_pitch".into(),
                value: "16".into(),
            },
        ],
    };
    let binding_b = fat_query::attempt_generation::GeneratedAttemptBinding {
        binding_id: "compressed-size-run::g1".into(),
        inputs: vec![
            InputBinding {
                key: "arg_size".into(),
                value: "64".into(),
            },
            InputBinding {
                key: "width".into(),
                value: "8".into(),
            },
            InputBinding {
                key: "row_pitch".into(),
                value: "8".into(),
            },
        ],
    };

    let resolved_a =
        resolve_runtime_attempt_with_binding(&plan, &binding_a, 0).expect("resolve binding a");
    let resolved_b =
        resolve_runtime_attempt_with_binding(&plan, &binding_b, 0).expect("resolve binding b");

    assert_ne!(
        resolved_a.generated_input_bindings,
        resolved_b.generated_input_bindings
    );
    assert_eq!(resolved_a.argv, resolved_b.argv);
    assert_eq!(resolved_a.env, resolved_b.env);
}

#[test]
fn discovery_runtime_preserves_direct_shape_stride_bindings_in_resolved_argv() {
    let dir = tempfile::tempdir().expect("tempdir");
    let build_dir = dir.path().join("build");
    let artifact_dir = dir.path().join("artifacts");
    fs::create_dir_all(&build_dir).expect("create build dir");

    let plan = HarnessPlan {
        harness_id: "direct-shape-run".into(),
        kind: HarnessKind::ShapeStride,
        family: BugFamily::SizeStrideArithmetic,
        lane_id: "direct-shape-lane".into(),
        source_root: build_dir.display().to_string(),
        build_dir: build_dir.display().to_string(),
        launcher_command: vec!["/bin/echo".into()],
        base_command: vec!["/bin/echo".into()],
        argv_template: vec![
            ArgTemplate::Literal {
                value: "--width".into(),
            },
            ArgTemplate::Binding {
                key: "width".into(),
            },
            ArgTemplate::Literal {
                value: "--height".into(),
            },
            ArgTemplate::Binding {
                key: "height".into(),
            },
            ArgTemplate::Literal {
                value: "--row-pitch".into(),
            },
            ArgTemplate::Binding {
                key: "row_pitch".into(),
            },
            ArgTemplate::Literal {
                value: "--depth-pitch".into(),
            },
            ArgTemplate::Binding {
                key: "depth_pitch".into(),
            },
            ArgTemplate::Literal {
                value: "--payload-bytes".into(),
            },
            ArgTemplate::Binding {
                key: "payload_bytes".into(),
            },
        ],
        env_template: BTreeMap::new(),
        input_bindings: Vec::new(),
        param_domains: Vec::new(),
        generation_strategy: Default::default(),
        required_env: BTreeMap::new(),
        timeout_ms: 1_000,
        artifact_dir: artifact_dir.display().to_string(),
        sanitizer_mode: "asan".into(),
        trigger_recipe: vec![TriggerRecipeStep {
            kind: "pitch-depth-mismatch".into(),
            detail: "preserve multi-field shape semantics through runtime resolution".into(),
        }],
        expected_proof_classes: vec!["asan-heap-buffer-overflow".into()],
        state_hypothesis_id: None,
        forbidden_transition_id: None,
        attempted_transition_summary: None,
        attempt_plan_hash: "direct-shape-attempt".into(),
    };

    let binding_a = fat_query::attempt_generation::GeneratedAttemptBinding {
        binding_id: "direct-shape-run::g0".into(),
        inputs: vec![
            InputBinding {
                key: "width".into(),
                value: "4".into(),
            },
            InputBinding {
                key: "height".into(),
                value: "4".into(),
            },
            InputBinding {
                key: "row_pitch".into(),
                value: "16".into(),
            },
            InputBinding {
                key: "depth_pitch".into(),
                value: "64".into(),
            },
            InputBinding {
                key: "payload_bytes".into(),
                value: "64".into(),
            },
        ],
    };
    let binding_b = fat_query::attempt_generation::GeneratedAttemptBinding {
        binding_id: "direct-shape-run::g1".into(),
        inputs: vec![
            InputBinding {
                key: "width".into(),
                value: "8".into(),
            },
            InputBinding {
                key: "height".into(),
                value: "4".into(),
            },
            InputBinding {
                key: "row_pitch".into(),
                value: "32".into(),
            },
            InputBinding {
                key: "depth_pitch".into(),
                value: "128".into(),
            },
            InputBinding {
                key: "payload_bytes".into(),
                value: "96".into(),
            },
        ],
    };

    let resolved_a =
        resolve_runtime_attempt_with_binding(&plan, &binding_a, 0).expect("resolve binding a");
    let resolved_b =
        resolve_runtime_attempt_with_binding(&plan, &binding_b, 0).expect("resolve binding b");

    assert_ne!(resolved_a.argv, resolved_b.argv);
    assert_eq!(
        resolved_a.argv,
        vec![
            "/bin/echo".to_string(),
            "--width".to_string(),
            "4".to_string(),
            "--height".to_string(),
            "4".to_string(),
            "--row-pitch".to_string(),
            "16".to_string(),
            "--depth-pitch".to_string(),
            "64".to_string(),
            "--payload-bytes".to_string(),
            "64".to_string(),
        ]
    );
}

#[test]
fn discovery_runtime_preserves_direct_lifetime_bindings_in_resolved_argv() {
    let dir = tempfile::tempdir().expect("tempdir");
    let build_dir = dir.path().join("build");
    let artifact_dir = dir.path().join("artifacts");
    fs::create_dir_all(&build_dir).expect("create build dir");

    let plan = HarnessPlan {
        harness_id: "direct-lifetime-run".into(),
        kind: HarnessKind::ReentrancyTeardown,
        family: BugFamily::LifetimeReentrancy,
        lane_id: "direct-lifetime-lane".into(),
        source_root: build_dir.display().to_string(),
        build_dir: build_dir.display().to_string(),
        launcher_command: vec!["/bin/echo".into()],
        base_command: vec!["/bin/echo".into()],
        argv_template: vec![
            ArgTemplate::Literal {
                value: "--callback-count".into(),
            },
            ArgTemplate::Binding {
                key: "callback_count".into(),
            },
            ArgTemplate::Literal {
                value: "--teardown-mode".into(),
            },
            ArgTemplate::Binding {
                key: "teardown_mode".into(),
            },
            ArgTemplate::Literal {
                value: "--cancellation-mode".into(),
            },
            ArgTemplate::Binding {
                key: "cancellation_mode".into(),
            },
        ],
        env_template: BTreeMap::new(),
        input_bindings: Vec::new(),
        param_domains: Vec::new(),
        generation_strategy: Default::default(),
        required_env: BTreeMap::new(),
        timeout_ms: 1_000,
        artifact_dir: artifact_dir.display().to_string(),
        sanitizer_mode: "asan".into(),
        trigger_recipe: vec![TriggerRecipeStep {
            kind: "destroy-owner-during-callback".into(),
            detail: "preserve lifetime controls through runtime resolution".into(),
        }],
        expected_proof_classes: vec!["asan-use-after-free".into()],
        state_hypothesis_id: None,
        forbidden_transition_id: None,
        attempted_transition_summary: None,
        attempt_plan_hash: "direct-lifetime-attempt".into(),
    };

    let binding = fat_query::attempt_generation::GeneratedAttemptBinding {
        binding_id: "direct-lifetime-run::g0".into(),
        inputs: vec![
            InputBinding {
                key: "callback_count".into(),
                value: "2".into(),
            },
            InputBinding {
                key: "teardown_mode".into(),
                value: "destroy-owner".into(),
            },
            InputBinding {
                key: "cancellation_mode".into(),
                value: "cancel-before-completion".into(),
            },
        ],
    };

    let resolved =
        resolve_runtime_attempt_with_binding(&plan, &binding, 0).expect("resolve binding");

    assert_eq!(
        resolved.argv,
        vec![
            "/bin/echo".to_string(),
            "--callback-count".to_string(),
            "2".to_string(),
            "--teardown-mode".to_string(),
            "destroy-owner".to_string(),
            "--cancellation-mode".to_string(),
            "cancel-before-completion".to_string(),
        ]
    );
}

#[test]
fn discovery_runtime_rejects_templated_attempts_with_missing_bindings() {
    let dir = tempfile::tempdir().expect("tempdir");
    let build_dir = dir.path().join("build");
    let artifact_dir = dir.path().join("artifacts");
    fs::create_dir_all(&build_dir).expect("create build dir");

    let plan = HarnessPlan {
        harness_id: "templated-missing-binding".into(),
        kind: HarnessKind::TrustBoundary,
        family: BugFamily::ValidationTrustBoundary,
        lane_id: "validation-lane".into(),
        source_root: build_dir.display().to_string(),
        build_dir: build_dir.display().to_string(),
        launcher_command: vec!["/bin/echo".into()],
        base_command: vec!["/bin/echo".into()],
        argv_template: vec![ArgTemplate::Binding {
            key: "missing_payload".into(),
        }],
        env_template: BTreeMap::new(),
        input_bindings: Vec::new(),
        param_domains: Vec::new(),
        generation_strategy: Default::default(),
        required_env: BTreeMap::new(),
        timeout_ms: 500,
        artifact_dir: artifact_dir.display().to_string(),
        sanitizer_mode: "asan".into(),
        trigger_recipe: vec![TriggerRecipeStep {
            kind: "malformed-mojo-or-webidl-payload".into(),
            detail: "missing payload binding should fail before launch".into(),
        }],
        expected_proof_classes: vec!["bad-message".into()],
        state_hypothesis_id: None,
        forbidden_transition_id: None,
        attempted_transition_summary: None,
        attempt_plan_hash: "templated-missing-binding-hash".into(),
    };

    let err = resolve_runtime_attempt(&plan, 0).expect_err("missing binding should fail");
    assert!(err.contains("missing binding"), "{err}");
    assert!(err.contains("missing_payload"), "{err}");
}

#[test]
fn discovery_runtime_resolves_distinct_generated_attempts_from_one_plan() {
    let dir = tempfile::tempdir().expect("tempdir");
    let build_dir = dir.path().join("build");
    let artifact_dir = dir.path().join("artifacts");
    fs::create_dir_all(&build_dir).expect("create build dir");
    fs::write(build_dir.join("vk_swiftshader_icd.json"), "{}").expect("write icd");

    let script_path = build_dir.join("angle_cl_argsize_repro_manual_asan23");
    fs::write(
        &script_path,
        "#!/bin/sh\nprintf 'ERROR: AddressSanitizer: heap-buffer-overflow' 1>&2\n",
    )
    .expect("write script");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = fs::metadata(&script_path).expect("metadata").permissions();
        permissions.set_mode(0o755);
        fs::set_permissions(&script_path, permissions).expect("chmod");
    }

    let plan = HarnessPlan {
        harness_id: "real-angle-generated".into(),
        kind: HarnessKind::ShapeStride,
        family: BugFamily::SizeStrideArithmetic,
        lane_id: "real-angle-lane".into(),
        source_root: build_dir.display().to_string(),
        build_dir: build_dir.display().to_string(),
        launcher_command: vec![script_path.display().to_string()],
        base_command: vec![script_path.display().to_string()],
        argv_template: vec![ArgTemplate::Binding {
            key: "arg_size".into(),
        }],
        env_template: BTreeMap::from([(
            "VK_ICD_FILENAMES".into(),
            EnvTemplate::Binding {
                key: "vk_icd_filenames".into(),
            },
        )]),
        input_bindings: vec![
            InputBinding {
                key: "width".into(),
                value: "4".into(),
            },
            InputBinding {
                key: "height".into(),
                value: "4".into(),
            },
            InputBinding {
                key: "row_pitch".into(),
                value: "16".into(),
            },
            InputBinding {
                key: "depth_pitch".into(),
                value: "64".into(),
            },
            InputBinding {
                key: "payload_bytes".into(),
                value: "64".into(),
            },
            InputBinding {
                key: "vk_icd_filenames".into(),
                value: build_dir
                    .join("vk_swiftshader_icd.json")
                    .display()
                    .to_string(),
            },
        ],
        param_domains: vec![
            ParamDomain {
                name: "width".into(),
                kind: ParamKind::Integer,
                seeds: vec!["4".into()],
                edge_cases: Vec::new(),
            },
            ParamDomain {
                name: "height".into(),
                kind: ParamKind::Integer,
                seeds: vec!["4".into()],
                edge_cases: Vec::new(),
            },
            ParamDomain {
                name: "row_pitch".into(),
                kind: ParamKind::Integer,
                seeds: vec!["16".into()],
                edge_cases: vec!["32".into()],
            },
            ParamDomain {
                name: "depth_pitch".into(),
                kind: ParamKind::Integer,
                seeds: vec!["64".into()],
                edge_cases: vec!["96".into()],
            },
            ParamDomain {
                name: "payload_bytes".into(),
                kind: ParamKind::Integer,
                seeds: vec!["64".into()],
                edge_cases: vec!["63".into(), "32".into()],
            },
            ParamDomain {
                name: "vk_icd_filenames".into(),
                kind: ParamKind::Path,
                seeds: vec![build_dir
                    .join("vk_swiftshader_icd.json")
                    .display()
                    .to_string()],
                edge_cases: Vec::new(),
            },
        ],
        generation_strategy: GenerationStrategy::FocusedEdgeSweep,
        required_env: BTreeMap::from([("ASAN_OPTIONS".into(), "symbolize=1".into())]),
        timeout_ms: 1_500,
        artifact_dir: artifact_dir.display().to_string(),
        sanitizer_mode: "asan".into(),
        trigger_recipe: vec![TriggerRecipeStep {
            kind: "pitch-depth-mismatch".into(),
            detail: "drive a real arg-size mismatch".into(),
        }],
        expected_proof_classes: vec!["asan-heap-buffer-overflow".into()],
        state_hypothesis_id: None,
        forbidden_transition_id: None,
        attempted_transition_summary: None,
        attempt_plan_hash: "templated-generated-attempt".into(),
    };

    let generated = generate_attempt_bindings(&plan);
    assert_eq!(generated.len(), 5, "{generated:#?}");
    assert!(generated
        .iter()
        .all(|binding| binding.inputs.iter().any(|input| input.key == "arg_size")));

    let first = resolve_runtime_attempt_with_binding(&plan, &generated[0], 0)
        .expect("resolve first generated attempt");
    let second = resolve_runtime_attempt_with_binding(&plan, &generated[1], 0)
        .expect("resolve second generated attempt");

    assert_ne!(first.attempt_id, second.attempt_id);
    assert_ne!(first.argv, second.argv);
    assert_eq!(first.argv[1], "64");
    assert_eq!(second.argv[1], "127");
    assert_eq!(
        first.env.get("VK_ICD_FILENAMES"),
        second.env.get("VK_ICD_FILENAMES")
    );

    let executed = execute_harness_plan_with_binding(&plan, &generated[2], 0)
        .expect("execute generated attempt");
    assert_eq!(
        executed.attempt.lifecycle,
        DiscoveryLifecycleStatus::Completed
    );
    assert_eq!(
        executed.attempt.generated_binding_id.as_deref(),
        Some("real-angle-generated::g2")
    );
}
