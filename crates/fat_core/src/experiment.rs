use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExperimentBundle {
    pub schema_version: String,
    #[serde(default)]
    pub bound_records: BTreeMap<String, Value>,
    #[serde(default)]
    pub artifacts: BTreeMap<String, Value>,
    pub experiment: ExperimentRecord,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ExperimentRecord {
    #[serde(default)]
    pub id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub record_digest: Option<String>,
    #[serde(default)]
    pub record_status: Option<String>,
    pub proof_ladder: ProofLadder,
    pub verdict: ExperimentVerdict,
    pub cleanup: ExperimentCleanup,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProofLadder {
    #[serde(default)]
    pub reached_predicates: Vec<String>,
    #[serde(default)]
    pub predicate_evidence: BTreeMap<String, PredicateEvidence>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PredicateEvidence {
    pub artifact_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExperimentVerdict {
    pub compatibility: String,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExperimentCleanup {
    pub status: String,
    #[serde(default)]
    pub artifact_digest: Option<String>,
    #[serde(flatten)]
    pub extra: BTreeMap<String, Value>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ExperimentValidationError {
    pub code: &'static str,
    pub path: String,
    pub message: String,
}

pub fn validate_experiment_bundle(
    bundle: &ExperimentBundle,
) -> Result<(), Vec<ExperimentValidationError>> {
    let mut errors = Vec::new();

    if bundle.schema_version != "1.0" {
        errors.push(ExperimentValidationError {
            code: "schema-version-unsupported",
            path: "schema_version".to_string(),
            message: format!(
                "unsupported experiment schema {}; expected 1.0",
                bundle.schema_version
            ),
        });
    }

    collect_invalid_numbers(
        &serde_json::to_value(bundle).expect("experiment bundle serialization cannot fail"),
        "",
        &mut errors,
    );

    match bundle.experiment.record_status.as_deref() {
        Some("started" | "finalized") => {}
        _ => errors.push(ExperimentValidationError {
            code: "record-status-invalid",
            path: "experiment.record_status".to_string(),
            message: "record status must be started or finalized".to_string(),
        }),
    }
    validate_experiment_contract(bundle, &mut errors);
    validate_launch_envelope(bundle, &mut errors);

    for (binding, prefix) in [
        ("target_requirement", "tgt"),
        ("machine_profile", "mch"),
        ("kernel_build_profile", "knl"),
        ("guest_contract", "gst"),
        ("goal_profile", "gol"),
    ] {
        let Some(record) = bundle.bound_records.get(binding) else {
            errors.push(ExperimentValidationError {
                code: "binding-missing",
                path: format!("bound_records.{binding}"),
                message: format!("required bound record {binding} is missing"),
            });
            continue;
        };

        let digest = record.get("record_digest").and_then(Value::as_str);
        if !digest.is_some_and(is_sha256_digest) {
            errors.push(ExperimentValidationError {
                code: "binding-digest-invalid",
                path: format!("bound_records.{binding}.record_digest"),
                message: "record digest must use sha256:<64 lowercase hex characters>".to_string(),
            });
        } else if let Some(body) = record.get("body") {
            let actual = canonical_record_digest(body);
            if digest != Some(actual.as_str()) {
                errors.push(ExperimentValidationError {
                    code: "binding-content-digest-mismatch",
                    path: format!("bound_records.{binding}.record_digest"),
                    message: format!(
                        "record digest does not match canonical embedded body: {actual}"
                    ),
                });
            }
            let suffix = &actual["sha256:".len()..][..16];
            let expected_id = format!("{prefix}-{suffix}");
            if record.get("id").and_then(Value::as_str) != Some(expected_id.as_str()) {
                errors.push(ExperimentValidationError {
                    code: "binding-id-digest-mismatch",
                    path: format!("bound_records.{binding}.id"),
                    message: format!("bound record ID must be {expected_id}"),
                });
            }

            let artifact_pointer = role_artifact_pointer(binding);
            if let Some((pointer, display_path)) = artifact_pointer {
                let artifact_digest = body.pointer(pointer).and_then(Value::as_str);
                if !artifact_digest.is_some_and(is_sha256_digest) {
                    errors.push(ExperimentValidationError {
                        code: "binding-artifact-digest-missing",
                        path: format!("bound_records.{binding}.body.{display_path}"),
                        message: "binding must pin its prelaunch artifact with SHA-256".to_string(),
                    });
                }
            }
            match binding {
                "target_requirement" => validate_target_body(body, &mut errors),
                "machine_profile" => validate_machine_body(body, &mut errors),
                "kernel_build_profile" => validate_kernel_body(body, &mut errors),
                "guest_contract" => validate_guest_body(body, &mut errors),
                "goal_profile" => validate_goal_body(body, &mut errors),
                _ => unreachable!("binding names are fixed above"),
            }
        } else {
            errors.push(ExperimentValidationError {
                code: "binding-body-missing",
                path: format!("bound_records.{binding}.body"),
                message: "bound record must embed its canonical body".to_string(),
            });
        }
    }

    for (digest, artifact) in &bundle.artifacts {
        let content = artifact.get("content_utf8").and_then(Value::as_str);
        let actual =
            content.map(|content| format!("sha256:{:x}", Sha256::digest(content.as_bytes())));
        if actual.as_deref() != Some(digest.as_str()) {
            errors.push(ExperimentValidationError {
                code: "artifact-content-digest-mismatch",
                path: format!("artifacts.{digest}"),
                message: "artifact key must equal the SHA-256 digest of content_utf8".to_string(),
            });
        }
    }

    for predicate in &bundle.experiment.proof_ladder.reached_predicates {
        let evidence = bundle
            .experiment
            .proof_ladder
            .predicate_evidence
            .get(predicate);
        if evidence.is_none() {
            errors.push(ExperimentValidationError {
                code: "predicate-evidence-missing",
                path: format!("experiment.proof_ladder.predicate_evidence.{predicate}"),
                message: format!("reached predicate {predicate} has no persisted evidence"),
            });
        } else if !evidence.is_some_and(|entry| is_sha256_digest(&entry.artifact_digest)) {
            errors.push(ExperimentValidationError {
                code: "predicate-artifact-digest-invalid",
                path: format!(
                    "experiment.proof_ladder.predicate_evidence.{predicate}.artifact_digest"
                ),
                message: format!(
                    "evidence for reached predicate {predicate} must reference a SHA-256 artifact"
                ),
            });
        } else if evidence
            .is_some_and(|entry| !bundle.artifacts.contains_key(&entry.artifact_digest))
        {
            errors.push(ExperimentValidationError {
                code: "predicate-artifact-missing",
                path: format!(
                    "experiment.proof_ladder.predicate_evidence.{predicate}.artifact_digest"
                ),
                message: format!("evidence artifact for {predicate} is not embedded in the bundle"),
            });
        }
    }

    if bundle.experiment.record_status.as_deref() == Some("finalized") {
        validate_final_record_digest(bundle, &mut errors);
    }

    if matches!(
        bundle.experiment.verdict.compatibility.as_str(),
        "supported" | "partial"
    ) && bundle.experiment.cleanup.status != "passed"
    {
        errors.push(ExperimentValidationError {
            code: "cleanup-gates-verdict",
            path: "experiment.cleanup.status".to_string(),
            message: format!(
                "{} verdict requires cleanup status passed",
                bundle.experiment.verdict.compatibility
            ),
        });
    }

    if bundle.experiment.cleanup.status == "passed" {
        let cleanup_digest = bundle.experiment.cleanup.artifact_digest.as_deref();
        if !cleanup_digest
            .is_some_and(|digest| is_sha256_digest(digest) && bundle.artifacts.contains_key(digest))
        {
            errors.push(ExperimentValidationError {
                code: "cleanup-artifact-missing",
                path: "experiment.cleanup.artifact_digest".to_string(),
                message: "passed cleanup requires embedded artifact-backed evidence".to_string(),
            });
        }
    }

    errors.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.code.cmp(right.code))
            .then_with(|| left.message.cmp(&right.message))
    });
    errors.dedup();

    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

pub fn validate_profile_record(
    binding: &str,
    record: &Value,
) -> Result<(), Vec<ExperimentValidationError>> {
    let prefix = match binding {
        "target_requirement" => "tgt",
        "machine_profile" => "mch",
        "kernel_build_profile" => "knl",
        "guest_contract" => "gst",
        "goal_profile" => "gol",
        _ => {
            return Err(vec![ExperimentValidationError {
                code: "binding-role-invalid",
                path: format!("bound_records.{binding}"),
                message: "unknown bound record role".to_string(),
            }]);
        }
    };
    let mut errors = Vec::new();
    let Some(body) = record.get("body") else {
        return Err(vec![ExperimentValidationError {
            code: "binding-body-missing",
            path: format!("bound_records.{binding}.body"),
            message: "bound record must embed its canonical body".to_string(),
        }]);
    };
    collect_invalid_numbers(body, &format!("bound_records.{binding}.body"), &mut errors);
    let actual = canonical_record_digest(body);
    if record.get("record_digest").and_then(Value::as_str) != Some(actual.as_str()) {
        errors.push(ExperimentValidationError {
            code: "binding-content-digest-mismatch",
            path: format!("bound_records.{binding}.record_digest"),
            message: format!("record digest does not match canonical embedded body: {actual}"),
        });
    }
    let expected_id = format!("{prefix}-{}", &actual["sha256:".len()..][..16]);
    if record.get("id").and_then(Value::as_str) != Some(expected_id.as_str()) {
        errors.push(ExperimentValidationError {
            code: "binding-id-digest-mismatch",
            path: format!("bound_records.{binding}.id"),
            message: format!("bound record ID must be {expected_id}"),
        });
    }
    if let Some((pointer, display_path)) = role_artifact_pointer(binding) {
        if !body
            .pointer(pointer)
            .and_then(Value::as_str)
            .is_some_and(is_sha256_digest)
        {
            errors.push(ExperimentValidationError {
                code: "binding-artifact-digest-missing",
                path: format!("bound_records.{binding}.body.{display_path}"),
                message: "binding must pin its prelaunch artifact with SHA-256".to_string(),
            });
        }
    }
    match binding {
        "target_requirement" => validate_target_body(body, &mut errors),
        "machine_profile" => validate_machine_body(body, &mut errors),
        "kernel_build_profile" => validate_kernel_body(body, &mut errors),
        "guest_contract" => validate_guest_body(body, &mut errors),
        "goal_profile" => validate_goal_body(body, &mut errors),
        _ => unreachable!("binding was checked above"),
    }
    finish_validation(errors)
}

pub fn validate_started_bundle(
    bundle: &ExperimentBundle,
) -> Result<(), Vec<ExperimentValidationError>> {
    let mut errors = validation_errors(bundle);
    if bundle.experiment.record_status.as_deref() != Some("started") {
        errors.push(ExperimentValidationError {
            code: "started-status-invalid",
            path: "experiment.record_status".to_string(),
            message: "started bundle must use record_status started".to_string(),
        });
    }
    if bundle.experiment.record_digest.is_some() {
        errors.push(ExperimentValidationError {
            code: "started-record-digest-present",
            path: "experiment.record_digest".to_string(),
            message: "started bundle cannot have a final record digest".to_string(),
        });
    }
    validate_launch_envelope(bundle, &mut errors);
    if bundle
        .experiment
        .extra
        .get("execution")
        .and_then(|execution| execution.get("started_at"))
        .and_then(Value::as_str)
        .is_none()
    {
        errors.push(ExperimentValidationError {
            code: "started-at-missing",
            path: "experiment.execution.started_at".to_string(),
            message: "started bundle must freeze execution.started_at".to_string(),
        });
    }
    if bundle
        .experiment
        .extra
        .get("execution")
        .and_then(|execution| execution.get("finished_at"))
        .is_some()
    {
        errors.push(ExperimentValidationError {
            code: "started-finished-at-present",
            path: "experiment.execution.finished_at".to_string(),
            message: "started bundle cannot already have execution.finished_at".to_string(),
        });
    }
    finish_validation(errors)
}

pub fn validate_finalization(
    started: &ExperimentBundle,
    finalized: &ExperimentBundle,
) -> Result<(), Vec<ExperimentValidationError>> {
    let mut errors = Vec::new();
    if let Err(start_errors) = validate_started_bundle(started) {
        errors.extend(start_errors);
    }
    if let Err(final_errors) = validate_experiment_bundle(finalized) {
        errors.extend(final_errors);
    }
    if finalized.experiment.record_status.as_deref() != Some("finalized") {
        errors.push(ExperimentValidationError {
            code: "finalized-status-invalid",
            path: "experiment.record_status".to_string(),
            message: "final bundle must use record_status finalized".to_string(),
        });
    }
    if started.bound_records != finalized.bound_records {
        errors.push(ExperimentValidationError {
            code: "finalization-binding-changed",
            path: "bound_records".to_string(),
            message: "bound records are immutable after start".to_string(),
        });
    }
    if started.experiment.id != finalized.experiment.id {
        errors.push(ExperimentValidationError {
            code: "finalization-id-changed",
            path: "experiment.id".to_string(),
            message: "experiment launch identity is immutable after start".to_string(),
        });
    }
    compare_immutable_extra_field(started, finalized, "launch_envelope", &mut errors);
    for field in ["experiment_type", "derived_from_experiment_id", "one_delta"] {
        compare_immutable_extra_field(started, finalized, field, &mut errors);
    }
    compare_started_execution(started, finalized, &mut errors);
    compare_started_interventions(started, finalized, &mut errors);
    compare_started_evidence(started, finalized, &mut errors);
    compare_started_artifacts(started, finalized, &mut errors);
    if finalized
        .experiment
        .extra
        .get("execution")
        .and_then(|execution| execution.get("finished_at"))
        .and_then(Value::as_str)
        .is_none()
    {
        errors.push(ExperimentValidationError {
            code: "finished-at-missing",
            path: "experiment.execution.finished_at".to_string(),
            message: "finalized experiment requires execution.finished_at".to_string(),
        });
    }
    finish_validation(errors)
}

pub fn validate_experiment_supersession(
    previous: &ExperimentBundle,
    correction: &ExperimentBundle,
) -> Result<(), Vec<ExperimentValidationError>> {
    let mut errors = validation_errors(previous);
    errors.extend(validation_errors(correction));
    if previous.experiment.id != correction.experiment.id
        || previous.bound_records != correction.bound_records
        || previous.experiment.extra.get("launch_envelope")
            != correction.experiment.extra.get("launch_envelope")
    {
        errors.push(ExperimentValidationError {
            code: "supersession-launch-changed",
            path: "experiment.launch_envelope".to_string(),
            message: "evidence correction must preserve launch identity and bindings".to_string(),
        });
    }
    let previous_digest = previous.experiment.record_digest.as_deref();
    let declared = correction
        .experiment
        .extra
        .get("supersedes_record_digest")
        .and_then(Value::as_str);
    if declared != previous_digest {
        errors.push(ExperimentValidationError {
            code: "supersedes-digest-missing",
            path: "experiment.supersedes_record_digest".to_string(),
            message: "correction must reference the exact prior final record digest".to_string(),
        });
    }
    finish_validation(errors)
}

fn validation_errors(bundle: &ExperimentBundle) -> Vec<ExperimentValidationError> {
    validate_experiment_bundle(bundle).err().unwrap_or_default()
}

fn validate_launch_envelope(
    bundle: &ExperimentBundle,
    errors: &mut Vec<ExperimentValidationError>,
) {
    let Some(envelope) = bundle.experiment.extra.get("launch_envelope") else {
        errors.push(ExperimentValidationError {
            code: "experiment-launch-envelope-missing",
            path: "experiment.launch_envelope".to_string(),
            message: "experiment requires an immutable launch envelope".to_string(),
        });
        return;
    };
    let digest = canonical_record_digest(envelope);
    let expected_id = format!("exp-{}", &digest["sha256:".len()..][..16]);
    if bundle.experiment.id.as_deref() != Some(expected_id.as_str()) {
        errors.push(ExperimentValidationError {
            code: "experiment-id-envelope-mismatch",
            path: "experiment.id".to_string(),
            message: format!("experiment ID must be {expected_id}"),
        });
    }
    for binding in [
        "target_requirement",
        "machine_profile",
        "kernel_build_profile",
        "guest_contract",
        "goal_profile",
    ] {
        let envelope_id = envelope
            .pointer(format!("/bindings/{binding}").as_str())
            .and_then(Value::as_str);
        let bound_id = bundle
            .bound_records
            .get(binding)
            .and_then(|record| record.get("id"))
            .and_then(Value::as_str);
        if envelope_id != bound_id {
            errors.push(ExperimentValidationError {
                code: "launch-binding-mismatch",
                path: format!("experiment.launch_envelope.bindings.{binding}"),
                message: format!(
                    "launch envelope binds {envelope_id:?}, but embedded record is {bound_id:?}"
                ),
            });
        }
    }
}

fn compare_immutable_extra_field(
    started: &ExperimentBundle,
    finalized: &ExperimentBundle,
    field: &str,
    errors: &mut Vec<ExperimentValidationError>,
) {
    if started.experiment.extra.get(field) != finalized.experiment.extra.get(field) {
        errors.push(ExperimentValidationError {
            code: "finalization-immutable-field-changed",
            path: format!("experiment.{field}"),
            message: format!("experiment.{field} is immutable after start"),
        });
    }
}

fn compare_started_execution(
    started: &ExperimentBundle,
    finalized: &ExperimentBundle,
    errors: &mut Vec<ExperimentValidationError>,
) {
    let Some(started_execution) = started
        .experiment
        .extra
        .get("execution")
        .and_then(Value::as_object)
    else {
        return;
    };
    let finalized_execution = finalized
        .experiment
        .extra
        .get("execution")
        .and_then(Value::as_object);
    for (field, started_value) in started_execution {
        if field == "finished_at" {
            continue;
        }
        let final_value = finalized_execution.and_then(|execution| execution.get(field));
        if final_value != Some(started_value) {
            errors.push(ExperimentValidationError {
                code: "finalization-immutable-field-changed",
                path: format!("experiment.execution.{field}"),
                message: format!("execution.{field} is immutable after start"),
            });
        }
    }
}

fn compare_started_interventions(
    started: &ExperimentBundle,
    finalized: &ExperimentBundle,
    errors: &mut Vec<ExperimentValidationError>,
) {
    let started_items = started
        .experiment
        .extra
        .get("interventions_applied")
        .and_then(Value::as_array);
    let finalized_items = finalized
        .experiment
        .extra
        .get("interventions_applied")
        .and_then(Value::as_array);
    let (Some(started_items), Some(finalized_items)) = (started_items, finalized_items) else {
        return;
    };
    if started_items.len() != finalized_items.len() {
        errors.push(ExperimentValidationError {
            code: "finalization-interventions-changed",
            path: "experiment.interventions_applied".to_string(),
            message: "intervention list is immutable after start".to_string(),
        });
        return;
    }
    for (index, (started_item, finalized_item)) in
        started_items.iter().zip(finalized_items).enumerate()
    {
        let (Some(started_item), Some(finalized_item)) =
            (started_item.as_object(), finalized_item.as_object())
        else {
            continue;
        };
        for (field, started_value) in started_item {
            if field == "verified" {
                continue;
            }
            if finalized_item.get(field) != Some(started_value) {
                errors.push(ExperimentValidationError {
                    code: "finalization-intervention-field-changed",
                    path: format!("experiment.interventions_applied.{index}.{field}"),
                    message: format!("intervention {field} is immutable after start"),
                });
            }
        }
    }
}

fn compare_started_evidence(
    started: &ExperimentBundle,
    finalized: &ExperimentBundle,
    errors: &mut Vec<ExperimentValidationError>,
) {
    for predicate in &started.experiment.proof_ladder.reached_predicates {
        let started_evidence = started
            .experiment
            .proof_ladder
            .predicate_evidence
            .get(predicate);
        let finalized_evidence = finalized
            .experiment
            .proof_ladder
            .predicate_evidence
            .get(predicate);
        if !finalized
            .experiment
            .proof_ladder
            .reached_predicates
            .contains(predicate)
            || started_evidence != finalized_evidence
        {
            errors.push(ExperimentValidationError {
                code: "finalization-evidence-removed",
                path: format!("experiment.proof_ladder.{predicate}"),
                message: format!("started evidence for {predicate} must be preserved"),
            });
        }
    }
}

fn compare_started_artifacts(
    started: &ExperimentBundle,
    finalized: &ExperimentBundle,
    errors: &mut Vec<ExperimentValidationError>,
) {
    for (digest, artifact) in &started.artifacts {
        if finalized.artifacts.get(digest) != Some(artifact) {
            errors.push(ExperimentValidationError {
                code: "finalization-artifact-removed",
                path: format!("artifacts.{digest}"),
                message: "started artifacts are append-only".to_string(),
            });
        }
    }
}

fn finish_validation(
    mut errors: Vec<ExperimentValidationError>,
) -> Result<(), Vec<ExperimentValidationError>> {
    errors.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.code.cmp(right.code))
            .then_with(|| left.message.cmp(&right.message))
    });
    errors.dedup();
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn validate_target_body(body: &Value, errors: &mut Vec<ExperimentValidationError>) {
    for pointer in [
        "/schema_version",
        "/firmware_digest",
        "/project_id",
        "/target_id",
        "/evidence_sources",
        "/cpu/isa_family",
        "/cpu/isa_floor",
        "/cpu/width",
        "/cpu/endianness",
        "/cpu/required_extensions",
        "/cpu/confidence",
        "/userspace_abi/abi",
        "/userspace_abi/float_calling_convention",
        "/userspace_abi/confidence",
        "/userspace_abi/evidence",
        "/loader",
        "/memory/page_size_sensitivity/status",
        "/memory/executable_stack",
        "/memory/fixed_mappings",
        "/memory/confidence",
        "/kernel_surface",
        "/module_dependence/status",
        "/module_dependence/modules",
        "/module_dependence/confidence",
        "/boot_contract",
        "/environment",
        "/unresolved_hard_facts",
        "/normalized_at",
    ] {
        require_pointer(
            body,
            pointer,
            "target-field-missing",
            "target_requirement",
            errors,
        );
    }
    validate_enum(
        body,
        "/cpu/endianness",
        &["le", "be", "unknown"],
        "target-enum-invalid",
        "target_requirement",
        errors,
    );
    validate_enum(
        body,
        "/cpu/isa_floor",
        &[
            "mips1",
            "mips32r1",
            "mips32r2",
            "mips64r1",
            "mips64r2",
            "armv5",
            "armv6",
            "armv7",
            "armv8-a",
            "x86-i486",
            "x86-64-v1",
            "riscv64-g",
            "unknown",
        ],
        "target-enum-invalid",
        "target_requirement",
        errors,
    );
    validate_enum(
        body,
        "/userspace_abi/abi",
        &[
            "o32", "n32", "n64", "arm-eabi", "arm-oabi", "lp64", "ilp32", "i386", "unknown",
        ],
        "target-enum-invalid",
        "target_requirement",
        errors,
    );
    validate_enum(
        body,
        "/userspace_abi/float_calling_convention",
        &["soft", "softfp", "hard", "not-applicable", "unknown"],
        "target-enum-invalid",
        "target_requirement",
        errors,
    );
}

fn validate_machine_body(body: &Value, errors: &mut Vec<ExperimentValidationError>) {
    for pointer in [
        "/schema_version",
        "/fat_profile_revision",
        "/qemu_machine_type",
        "/qemu_versioned_machine_type",
        "/qemu/exact_version",
        "/qemu/binary_digest",
        "/qemu/binary_name",
        "/qemu/provenance",
        "/cpu/model",
        "/cpu/exposed_isa_floor",
        "/cpu/exposed_extensions",
        "/cpu/variants_tested",
        "/memory/ram_mb",
        "/console",
        "/block/root_device_mapping",
        "/network",
        "/firmware_inputs",
        "/launch_arguments/canonical_form",
        "/capabilities",
        "/known_incompatibilities",
        "/created_at",
    ] {
        require_pointer(
            body,
            pointer,
            "machine-field-missing",
            "machine_profile",
            errors,
        );
    }
}

fn validate_kernel_body(body: &Value, errors: &mut Vec<ExperimentValidationError>) {
    for pointer in [
        "/schema_version",
        "/class",
        "/support_tier",
        "/artifact_digest",
        "/architecture_contract/isa",
        "/architecture_contract/endianness",
        "/architecture_contract/userspace_abis_supported",
        "/architecture_contract/isa_floor",
        "/architecture_contract/page_size",
        "/capabilities",
        "/required_machine_capabilities",
        "/known_negative_evidence_ids",
        "/license",
        "/created_at",
    ] {
        require_pointer(
            body,
            pointer,
            "kernel-field-missing",
            "kernel_build_profile",
            errors,
        );
    }
    validate_enum(
        body,
        "/support_tier",
        &[
            "experimental",
            "supported",
            "external-required",
            "deprecated",
        ],
        "kernel-enum-invalid",
        "kernel_build_profile",
        errors,
    );
    validate_enum(
        body,
        "/architecture_contract/endianness",
        &["le", "be", "unknown"],
        "kernel-enum-invalid",
        "kernel_build_profile",
        errors,
    );
    validate_enum(
        body,
        "/architecture_contract/isa_floor",
        &[
            "mips1",
            "mips32r1",
            "mips32r2",
            "mips64r1",
            "mips64r2",
            "armv5",
            "armv6",
            "armv7",
            "armv8-a",
            "x86-i486",
            "x86-64-v1",
            "riscv64-g",
            "unknown",
        ],
        "kernel-enum-invalid",
        "kernel_build_profile",
        errors,
    );
    validate_enum(
        body,
        "/architecture_contract/page_size",
        &["4k", "16k", "64k", "unknown"],
        "kernel-enum-invalid",
        "kernel_build_profile",
        errors,
    );

    let support_tier = body.pointer("/support_tier").and_then(Value::as_str);
    if support_tier == Some("external-required") {
        for pointer in [
            "/attribution/project",
            "/attribution/source_location",
            "/attribution/redistributed_by_fat",
        ] {
            require_pointer(
                body,
                pointer,
                "kernel-field-missing",
                "kernel_build_profile",
                errors,
            );
        }
    } else {
        for pointer in [
            "/source/archive_digest",
            "/source/signature_verified",
            "/config/final_config_digest",
            "/toolchain/compiler_digest",
            "/artifacts/kernel_image/digest",
            "/reproducible_build/recipe_reproducible",
        ] {
            require_pointer(
                body,
                pointer,
                "kernel-field-missing",
                "kernel_build_profile",
                errors,
            );
        }
    }
}

fn validate_guest_body(body: &Value, errors: &mut Vec<ExperimentValidationError>) {
    for pointer in [
        "/schema_version",
        "/scope",
        "/assembled_rootfs_digest",
        "/rootfs/source_digest",
        "/rootfs/layers",
        "/rootfs/image_digest",
        "/pre_init/handoff_binary_digest",
        "/pre_init/handoff_type",
        "/pre_init/environment_clean",
        "/mounts",
        "/devices",
        "/nvram_adapters",
        "/network/interfaces",
        "/network/ports_forwarded",
        "/peer_dependencies",
        "/adaptations",
        "/teardown",
        "/created_at",
    ] {
        require_pointer(
            body,
            pointer,
            "guest-field-missing",
            "guest_contract",
            errors,
        );
    }

    let Some(adaptations) = body.pointer("/adaptations").and_then(Value::as_array) else {
        return;
    };
    for (index, adaptation) in adaptations.iter().enumerate() {
        for field in [
            "action",
            "description",
            "reason",
            "source_evidence",
            "scope",
            "reversible",
            "semantic_risk",
            "expected_predicate",
            "falsifier",
        ] {
            if adaptation.get(field).is_none() {
                errors.push(ExperimentValidationError {
                    code: "adaptation-field-missing",
                    path: format!("bound_records.guest_contract.body.adaptations[{index}].{field}"),
                    message: format!("guest adaptation requires {field}"),
                });
            }
        }
        validate_inline_enum(
            adaptation.get("action"),
            &[
                "CREATE_EXTERNAL_STATE",
                "START_PEER",
                "INFER_VALUE",
                "INJECT_ENV",
                "PATCH_CONFIG",
                "ADAPT_INTERFACE",
                "INTERPOSE_API",
                "PATCH_PROCESS",
                "PATCH_KERNEL",
                "STUB_DEVICE",
            ],
            "guest-enum-invalid",
            format!("bound_records.guest_contract.body.adaptations[{index}].action"),
            errors,
        );
        validate_inline_enum(
            adaptation.get("semantic_risk"),
            &["low", "medium", "medium-high", "high", "very-high"],
            "guest-enum-invalid",
            format!("bound_records.guest_contract.body.adaptations[{index}].semantic_risk"),
            errors,
        );
    }
}

fn validate_goal_body(body: &Value, errors: &mut Vec<ExperimentValidationError>) {
    for pointer in [
        "/schema_version",
        "/goal_name",
        "/execution_mode",
        "/proof_track",
        "/description",
        "/required_predicates",
        "/optional_predicates",
        "/prohibited_interventions",
        "/prohibited_intervention_rationale",
        "/fidelity_requirements",
        "/success_criteria",
        "/failure_is_informative",
        "/created_at",
    ] {
        require_pointer(body, pointer, "goal-field-missing", "goal_profile", errors);
    }
    validate_enum(
        body,
        "/execution_mode",
        &[
            "full-system",
            "service",
            "user-mode",
            "reconstructed-kernel",
            "reference-hardware",
        ],
        "goal-enum-invalid",
        "goal_profile",
        errors,
    );

    let track = body.pointer("/proof_track").and_then(Value::as_str);
    let registry = match track {
        Some("full-system-init-v1") => Some(
            &[
                "K0.kernel_entry",
                "K1.root_mount",
                "G0.fat_preinit",
                "G1.vendor_init",
            ][..],
        ),
        Some("full-system-service-v1") => Some(
            &[
                "K0.kernel_entry",
                "K1.root_mount",
                "G0.fat_preinit",
                "G1.vendor_init",
                "S0.service_process",
                "S1.listener",
                "S2.protocol_response",
                "A0.analysis_effect",
            ][..],
        ),
        _ => None,
    };
    if let (Some(order), Some(predicates)) = (
        registry,
        body.pointer("/required_predicates")
            .and_then(Value::as_array),
    ) {
        let positions = predicates
            .iter()
            .filter_map(Value::as_str)
            .map(|predicate| order.iter().position(|known| known == &predicate))
            .collect::<Vec<_>>();
        let valid = positions.iter().all(Option::is_some)
            && positions
                .windows(2)
                .all(|pair| pair[0].is_some_and(|left| pair[1].is_some_and(|right| left < right)));
        if !valid {
            errors.push(ExperimentValidationError {
                code: "goal-predicate-order-invalid",
                path: "bound_records.goal_profile.body.required_predicates".to_string(),
                message: "required predicates do not follow the declared proof track".to_string(),
            });
        }
    }
}

fn require_pointer(
    body: &Value,
    pointer: &str,
    code: &'static str,
    binding: &str,
    errors: &mut Vec<ExperimentValidationError>,
) {
    if body.pointer(pointer).is_none() {
        errors.push(ExperimentValidationError {
            code,
            path: format!(
                "bound_records.{binding}.body.{}",
                pointer.trim_start_matches('/').replace('/', ".")
            ),
            message: format!("required field {pointer} is missing"),
        });
    }
}

fn validate_enum(
    body: &Value,
    pointer: &str,
    allowed: &[&str],
    code: &'static str,
    binding: &str,
    errors: &mut Vec<ExperimentValidationError>,
) {
    validate_inline_enum(
        body.pointer(pointer),
        allowed,
        code,
        format!(
            "bound_records.{binding}.body.{}",
            pointer.trim_start_matches('/').replace('/', ".")
        ),
        errors,
    );
}

fn validate_inline_enum(
    value: Option<&Value>,
    allowed: &[&str],
    code: &'static str,
    path: String,
    errors: &mut Vec<ExperimentValidationError>,
) {
    let Some(value) = value else {
        return;
    };
    if !value.as_str().is_some_and(|value| allowed.contains(&value)) {
        errors.push(ExperimentValidationError {
            code,
            path,
            message: format!("value must be one of {}", allowed.join(", ")),
        });
    }
}

fn require_inline_enum(
    value: Option<&Value>,
    allowed: &[&str],
    code: &'static str,
    path: String,
    errors: &mut Vec<ExperimentValidationError>,
) {
    if value.is_none() {
        errors.push(ExperimentValidationError {
            code,
            path,
            message: format!("required value must be one of {}", allowed.join(", ")),
        });
    } else {
        validate_inline_enum(value, allowed, code, path, errors);
    }
}

fn role_artifact_pointer(binding: &str) -> Option<(&'static str, &'static str)> {
    match binding {
        "target_requirement" => Some(("/firmware_digest", "firmware_digest")),
        "machine_profile" => Some(("/qemu/binary_digest", "qemu.binary_digest")),
        "kernel_build_profile" => Some(("/artifact_digest", "artifact_digest")),
        "guest_contract" => Some(("/assembled_rootfs_digest", "assembled_rootfs_digest")),
        "goal_profile" => None,
        _ => None,
    }
}

fn validate_experiment_contract(
    bundle: &ExperimentBundle,
    errors: &mut Vec<ExperimentValidationError>,
) {
    let experiment = &bundle.experiment.extra;
    require_inline_enum(
        experiment.get("experiment_type"),
        &["full", "one-delta", "discovery", "counterfactual"],
        "experiment-type-invalid",
        "experiment.experiment_type".to_string(),
        errors,
    );
    if !experiment.contains_key("derived_from_experiment_id") {
        errors.push(ExperimentValidationError {
            code: "derived-experiment-id-missing",
            path: "experiment.derived_from_experiment_id".to_string(),
            message: "derived experiment identity must be explicit, including null".to_string(),
        });
    } else if experiment
        .get("derived_from_experiment_id")
        .is_some_and(|value| !value.is_null() && !is_experiment_id(value.as_str().unwrap_or("")))
    {
        errors.push(ExperimentValidationError {
            code: "derived-experiment-id-invalid",
            path: "experiment.derived_from_experiment_id".to_string(),
            message: "derived identity must be null or exp-<16 lowercase hex>".to_string(),
        });
    }
    if matches!(
        experiment.get("experiment_type").and_then(Value::as_str),
        Some("one-delta" | "counterfactual")
    ) && !experiment
        .get("derived_from_experiment_id")
        .is_some_and(|value| value.as_str().is_some_and(is_experiment_id))
    {
        errors.push(ExperimentValidationError {
            code: "derived-experiment-id-required",
            path: "experiment.derived_from_experiment_id".to_string(),
            message: "one-delta and counterfactual experiments require a parent experiment"
                .to_string(),
        });
    }
    if experiment.get("experiment_type").and_then(Value::as_str) == Some("one-delta")
        && !experiment.get("one_delta").is_some_and(Value::is_object)
    {
        errors.push(ExperimentValidationError {
            code: "one-delta-contract-missing",
            path: "experiment.one_delta".to_string(),
            message: "one-delta experiments require their prediction and falsifier contract"
                .to_string(),
        });
    }
    let execution = experiment.get("execution").and_then(Value::as_object);
    if execution.is_none() {
        errors.push(ExperimentValidationError {
            code: "experiment-execution-missing",
            path: "experiment.execution".to_string(),
            message: "experiment execution contract is required".to_string(),
        });
    }
    if !execution.is_some_and(|execution| execution.contains_key("timeout_seconds")) {
        errors.push(ExperimentValidationError {
            code: "execution-timeout-missing",
            path: "experiment.execution.timeout_seconds".to_string(),
            message: "timeout must be an integer or explicit null when historical evidence is unavailable"
                .to_string(),
        });
    } else if execution
        .and_then(|execution| execution.get("timeout_seconds"))
        .is_some_and(|value| !value.is_null() && value.as_u64().is_none_or(|value| value == 0))
    {
        errors.push(ExperimentValidationError {
            code: "execution-timeout-invalid",
            path: "experiment.execution.timeout_seconds".to_string(),
            message: "timeout must be a positive integer or explicit null".to_string(),
        });
    }
    require_inline_enum(
        execution.and_then(|execution| execution.get("network_isolation")),
        &[
            "user-mode-nat",
            "no-network",
            "bridge-isolated",
            "none",
            "unknown",
        ],
        "network-isolation-invalid",
        "experiment.execution.network_isolation".to_string(),
        errors,
    );

    if let (Some(launch), Some(execution)) = (
        experiment
            .get("launch_envelope")
            .and_then(|value| value.get("execution_inputs"))
            .and_then(Value::as_object),
        execution,
    ) {
        for field in [
            "backend_driver",
            "backend_revision",
            "host_platform",
            "launch_command_digest",
            "qemu_binary_digest",
            "qemu_version",
            "started_at",
            "substrate_kind",
            "timeout_seconds",
            "network_isolation",
        ] {
            if launch.get(field) != execution.get(field) {
                errors.push(ExperimentValidationError {
                    code: "launch-execution-mismatch",
                    path: format!("experiment.launch_envelope.execution_inputs.{field}"),
                    message: format!("launch envelope must freeze execution.{field}"),
                });
            }
        }
    }

    let interventions = experiment
        .get("interventions_applied")
        .and_then(Value::as_array);
    let guest_adaptations = bundle
        .bound_records
        .get("guest_contract")
        .and_then(|record| record.pointer("/body/adaptations"))
        .and_then(Value::as_array);
    if interventions.is_none() {
        errors.push(ExperimentValidationError {
            code: "interventions-applied-missing",
            path: "experiment.interventions_applied".to_string(),
            message: "applied interventions must be explicit, including an empty list".to_string(),
        });
    } else if interventions.map(Vec::len) != guest_adaptations.map(Vec::len) {
        errors.push(ExperimentValidationError {
            code: "intervention-count-mismatch",
            path: "experiment.interventions_applied".to_string(),
            message: "applied interventions must account for every bound guest-contract adaptation"
                .to_string(),
        });
    }
    if let Some(interventions) = interventions {
        let mut risk_counts = BTreeMap::<&str, u64>::new();
        for (index, intervention) in interventions.iter().enumerate() {
            for field in [
                "action",
                "description",
                "source_guest_contract_entry",
                "semantic_risk",
                "expected_predicate",
                "predicate_affected",
                "verified",
            ] {
                if intervention.get(field).is_none() {
                    errors.push(ExperimentValidationError {
                        code: "intervention-field-missing",
                        path: format!("experiment.interventions_applied.{index}.{field}"),
                        message: "intervention evidence field is required".to_string(),
                    });
                }
            }
            if intervention
                .get("verified")
                .and_then(Value::as_bool)
                .is_none()
            {
                errors.push(ExperimentValidationError {
                    code: "intervention-verification-invalid",
                    path: format!("experiment.interventions_applied.{index}.verified"),
                    message: "intervention verification must be boolean".to_string(),
                });
            }
            if bundle.experiment.record_status.as_deref() == Some("started")
                && intervention.get("verified").and_then(Value::as_bool) == Some(true)
            {
                errors.push(ExperimentValidationError {
                    code: "started-intervention-prematurely-verified",
                    path: format!("experiment.interventions_applied.{index}.verified"),
                    message: "started records cannot pre-claim intervention verification"
                        .to_string(),
                });
            }
            if let Some(risk) = intervention.get("semantic_risk").and_then(Value::as_str) {
                *risk_counts.entry(risk).or_default() += 1;
            }
            if let Some(adaptation) = guest_adaptations.and_then(|items| items.get(index)) {
                for field in [
                    "action",
                    "description",
                    "semantic_risk",
                    "expected_predicate",
                ] {
                    if intervention.get(field) != adaptation.get(field) {
                        errors.push(ExperimentValidationError {
                            code: "intervention-contract-mismatch",
                            path: format!("experiment.interventions_applied.{index}.{field}"),
                            message: format!(
                                "applied intervention must match guest adaptation {index}"
                            ),
                        });
                    }
                }
            }
        }
        if let Some(by_risk) = experiment
            .get("intervention_ledger")
            .and_then(|ledger| ledger.get("by_risk"))
            .and_then(Value::as_object)
        {
            for risk in ["low", "medium", "high", "very-high"] {
                if by_risk.get(risk).and_then(Value::as_u64)
                    != Some(*risk_counts.get(risk).unwrap_or(&0))
                {
                    errors.push(ExperimentValidationError {
                        code: "intervention-ledger-risk-mismatch",
                        path: format!("experiment.intervention_ledger.by_risk.{risk}"),
                        message: "ledger risk count must match interventions_applied".to_string(),
                    });
                }
            }
        } else {
            errors.push(ExperimentValidationError {
                code: "intervention-ledger-risk-missing",
                path: "experiment.intervention_ledger.by_risk".to_string(),
                message: "ledger must count low, medium, high, and very-high interventions"
                    .to_string(),
            });
        }
    }
    let ledger = experiment.get("intervention_ledger");
    if ledger.is_none() {
        errors.push(ExperimentValidationError {
            code: "intervention-ledger-missing",
            path: "experiment.intervention_ledger".to_string(),
            message: "intervention ledger is required".to_string(),
        });
    } else if ledger
        .and_then(|ledger| ledger.get("total_interventions"))
        .and_then(Value::as_u64)
        != interventions.map(|items| items.len() as u64)
    {
        errors.push(ExperimentValidationError {
            code: "intervention-ledger-total-mismatch",
            path: "experiment.intervention_ledger.total_interventions".to_string(),
            message: "ledger total must equal interventions_applied length".to_string(),
        });
    }
    let prohibited = bundle
        .bound_records
        .get("goal_profile")
        .and_then(|record| record.pointer("/body/prohibited_interventions"))
        .and_then(Value::as_array);
    let prohibited_count = interventions
        .into_iter()
        .flatten()
        .filter(|intervention| {
            let action = intervention.get("action").and_then(Value::as_str);
            prohibited.is_some_and(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .any(|item| Some(item) == action)
            })
        })
        .count() as u64;
    if ledger
        .and_then(|ledger| ledger.get("goal_prohibited_violations"))
        .and_then(Value::as_u64)
        != Some(prohibited_count)
    {
        errors.push(ExperimentValidationError {
            code: "intervention-ledger-prohibition-mismatch",
            path: "experiment.intervention_ledger.goal_prohibited_violations".to_string(),
            message: "ledger prohibited count must match goal policy".to_string(),
        });
    }
}

fn validate_final_record_digest(
    bundle: &ExperimentBundle,
    errors: &mut Vec<ExperimentValidationError>,
) {
    let Some(declared) = bundle.experiment.record_digest.as_deref() else {
        errors.push(ExperimentValidationError {
            code: "experiment-record-digest-missing",
            path: "experiment.record_digest".to_string(),
            message: "finalized record requires a canonical record digest".to_string(),
        });
        return;
    };
    if !is_sha256_digest(declared) {
        errors.push(ExperimentValidationError {
            code: "experiment-record-digest-missing",
            path: "experiment.record_digest".to_string(),
            message: "finalized record digest must use sha256:<64 lowercase hex>".to_string(),
        });
        return;
    }
    let actual = canonical_experiment_record_digest(&bundle.experiment);
    if declared != actual {
        errors.push(ExperimentValidationError {
            code: "experiment-record-digest-mismatch",
            path: "experiment.record_digest".to_string(),
            message: format!(
                "final record digest does not match canonical experiment content: {actual}"
            ),
        });
    }
}

fn collect_invalid_numbers(value: &Value, path: &str, errors: &mut Vec<ExperimentValidationError>) {
    match value {
        Value::Array(values) => {
            for (index, value) in values.iter().enumerate() {
                collect_invalid_numbers(value, &format!("{path}.{index}"), errors);
            }
        }
        Value::Object(values) => {
            for (key, value) in values {
                let child = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                collect_invalid_numbers(value, &child, errors);
            }
        }
        Value::Number(number) if !number.is_i64() && !number.is_u64() => {
            errors.push(ExperimentValidationError {
                code: "canonical-number-invalid",
                path: path.trim_start_matches('.').to_string(),
                message: "schema v1 canonical content permits integers but not floats".to_string(),
            });
        }
        _ => {}
    }
}

pub fn is_sha256_digest(value: &str) -> bool {
    value.strip_prefix("sha256:").is_some_and(|hex| {
        hex.len() == 64
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

fn is_experiment_id(value: &str) -> bool {
    value.strip_prefix("exp-").is_some_and(|hex| {
        hex.len() == 16
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    })
}

pub fn canonical_record_digest(value: &Value) -> String {
    let canonical = canonicalize_value(value);
    let encoded = serde_json::to_vec(&canonical).expect("JSON value serialization cannot fail");
    format!("sha256:{:x}", Sha256::digest(encoded))
}

pub fn canonical_experiment_record_digest(experiment: &ExperimentRecord) -> String {
    let mut value =
        serde_json::to_value(experiment).expect("experiment record serialization cannot fail");
    value
        .as_object_mut()
        .expect("experiment record serializes as an object")
        .remove("record_digest");
    canonical_record_digest(&value)
}

fn canonicalize_value(value: &Value) -> Value {
    match value {
        Value::Array(values) => Value::Array(values.iter().map(canonicalize_value).collect()),
        Value::Object(values) => {
            let sorted = values
                .iter()
                .map(|(key, value)| (key.clone(), canonicalize_value(value)))
                .collect::<std::collections::BTreeMap<_, _>>();
            Value::Object(sorted.into_iter().collect())
        }
        scalar => scalar.clone(),
    }
}
