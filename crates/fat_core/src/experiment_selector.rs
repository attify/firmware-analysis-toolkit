use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::experiment::{
    canonical_record_digest, is_sha256_digest, validate_experiment_bundle, validate_profile_record,
    ExperimentBundle, ExperimentValidationError,
};

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionRequest {
    pub schema_version: String,
    pub target_requirement: Value,
    pub goal_profile: Value,
    #[serde(default)]
    pub candidates: Vec<SelectionCandidate>,
    #[serde(default)]
    pub capability_mappings: Vec<CompatibilityMapping>,
    #[serde(default)]
    pub prior_experiments: Vec<ExperimentBundle>,
    #[serde(default)]
    pub negative_evidence: Vec<NegativeEvidenceRecord>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelectionCandidate {
    pub candidate_id: String,
    pub machine_profile: Value,
    pub kernel_build_profile: Value,
    pub guest_contract: Value,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CompatibilityMapping {
    pub kernel_requirement: String,
    pub machine_capability: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NegativeEvidenceRecord {
    pub id: String,
    pub record_digest: String,
    pub body: NegativeEvidenceBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NegativeEvidenceBody {
    pub candidate_id: String,
    pub target_id: String,
    pub failed_predicate: String,
    pub cause_status: String,
    pub evidence_experiment_id: String,
    pub tested_binding: BTreeMap<String, String>,
    pub retest_when: NegativeEvidenceRetest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NegativeEvidenceRetest {
    pub owning_layer: String,
    pub digest_fields: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SelectionStatus {
    Selected,
    ExactArtifactReplay,
    Discovery,
    Refusal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CandidateDisposition {
    Eligible,
    ExactArtifactReplay,
    Discovery,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectionReason {
    pub code: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CandidateDecision {
    pub candidate_id: String,
    pub disposition: CandidateDisposition,
    pub score: i64,
    pub reasons: Vec<SelectionReason>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SelectionResult {
    pub schema_version: String,
    pub status: SelectionStatus,
    pub selected_candidate_id: Option<String>,
    pub candidates: Vec<CandidateDecision>,
}

pub fn select_compatibility(
    request: &SelectionRequest,
) -> Result<SelectionResult, Vec<ExperimentValidationError>> {
    let mut request_errors = Vec::new();
    if request.schema_version != "1.0" {
        request_errors.push(ExperimentValidationError {
            code: "selector-schema-version-unsupported",
            path: "schema_version".to_string(),
            message: format!(
                "unsupported selector schema {}; expected 1.0",
                request.schema_version
            ),
        });
    }
    if let Err(errors) = validate_profile_record("target_requirement", &request.target_requirement)
    {
        request_errors.extend(errors);
    }
    if let Err(errors) = validate_profile_record("goal_profile", &request.goal_profile) {
        request_errors.extend(errors);
    }
    for (index, prior) in request.prior_experiments.iter().enumerate() {
        if let Err(errors) = validate_experiment_bundle(prior) {
            request_errors.extend(errors.into_iter().map(|mut error| {
                error.path = format!("prior_experiments.{index}.{}", error.path);
                error
            }));
        }
    }
    for (index, negative) in request.negative_evidence.iter().enumerate() {
        request_errors.extend(
            validate_negative_evidence(negative)
                .into_iter()
                .map(|mut error| {
                    error.path = format!("negative_evidence.{index}.{}", error.path);
                    error
                }),
        );
    }
    if !request_errors.is_empty() {
        request_errors.sort_by(|left, right| {
            left.path
                .cmp(&right.path)
                .then_with(|| left.code.cmp(right.code))
        });
        return Err(request_errors);
    }

    let unresolved = target_has_unresolved_hard_facts(&request.target_requirement);
    let mut decisions = request
        .candidates
        .iter()
        .map(|candidate| evaluate_candidate(request, candidate, unresolved))
        .collect::<Vec<_>>();
    decisions.sort_by(|left, right| left.candidate_id.cmp(&right.candidate_id));

    let eligible = best_candidate(&decisions, CandidateDisposition::Eligible);
    let exact = best_candidate(&decisions, CandidateDisposition::ExactArtifactReplay);
    let has_discovery = decisions
        .iter()
        .any(|decision| decision.disposition == CandidateDisposition::Discovery);
    let (status, selected_candidate_id) = if let Some(candidate) = eligible {
        (
            SelectionStatus::Selected,
            Some(candidate.candidate_id.clone()),
        )
    } else if let Some(candidate) = exact {
        (
            SelectionStatus::ExactArtifactReplay,
            Some(candidate.candidate_id.clone()),
        )
    } else if has_discovery {
        (SelectionStatus::Discovery, None)
    } else {
        (SelectionStatus::Refusal, None)
    };

    Ok(SelectionResult {
        schema_version: "1.0".to_string(),
        status,
        selected_candidate_id,
        candidates: decisions,
    })
}

fn evaluate_candidate(
    request: &SelectionRequest,
    candidate: &SelectionCandidate,
    unresolved: bool,
) -> CandidateDecision {
    let mut reasons = Vec::new();
    let mut rejected = false;
    for (role, record) in [
        ("machine_profile", &candidate.machine_profile),
        ("kernel_build_profile", &candidate.kernel_build_profile),
        ("guest_contract", &candidate.guest_contract),
    ] {
        if let Err(errors) = validate_profile_record(role, record) {
            rejected = true;
            for error in errors {
                reason(
                    &mut reasons,
                    "candidate-profile-invalid",
                    format!("{} [{}] {}", error.path, error.code, error.message),
                );
            }
        }
    }

    evaluate_architecture_contract(request, candidate, &mut reasons, &mut rejected);
    evaluate_machine_mappings(request, candidate, &mut reasons, &mut rejected);
    evaluate_prohibited_interventions(request, candidate, &mut reasons, &mut rejected);
    let negative_penalty =
        evaluate_negative_evidence(request, candidate, &mut reasons, &mut rejected);
    let prior_depth = matching_prior_depth(request, candidate);
    let semantic_risk = guest_semantic_risk(&candidate.guest_contract);
    let score = prior_depth as i64 * 100 - semantic_risk - negative_penalty;

    let disposition = if rejected {
        CandidateDisposition::Rejected
    } else if unresolved {
        reason(
            &mut reasons,
            "target-hard-facts-unresolved",
            "target ABI, ISA floor, endianness, or page-size facts remain unresolved",
        );
        if matching_prior_exact(request, candidate) {
            reason(
                &mut reasons,
                "exact-prior-evidence",
                "matching finalized evidence permits exact-artifact replay only",
            );
            CandidateDisposition::ExactArtifactReplay
        } else {
            CandidateDisposition::Discovery
        }
    } else {
        CandidateDisposition::Eligible
    };
    reasons.sort_by(|left, right| {
        left.code
            .cmp(&right.code)
            .then_with(|| left.message.cmp(&right.message))
    });
    reasons.dedup();
    CandidateDecision {
        candidate_id: candidate.candidate_id.clone(),
        disposition,
        score,
        reasons,
    }
}

fn evaluate_architecture_contract(
    request: &SelectionRequest,
    candidate: &SelectionCandidate,
    reasons: &mut Vec<SelectionReason>,
    rejected: &mut bool,
) {
    let target = &request.target_requirement["body"];
    let kernel = &candidate.kernel_build_profile["body"]["architecture_contract"];
    for (target_pointer, kernel_pointer, code) in [
        ("/cpu/isa_family", "/isa", "target-kernel-isa-conflict"),
        (
            "/cpu/endianness",
            "/endianness",
            "target-kernel-endianness-conflict",
        ),
    ] {
        let target_value = target.pointer(target_pointer).and_then(Value::as_str);
        let kernel_value = kernel.pointer(kernel_pointer).and_then(Value::as_str);
        if target_value.is_some_and(|value| value != "unknown")
            && kernel_value.is_some_and(|value| value != "unknown")
            && target_value != kernel_value
        {
            *rejected = true;
            reason(
                reasons,
                code,
                "target and kernel architecture contracts conflict",
            );
        }
    }
    let target_abi = target.pointer("/userspace_abi/abi").and_then(Value::as_str);
    let supported_abis = kernel
        .pointer("/userspace_abis_supported")
        .and_then(Value::as_array);
    if target_abi.is_some_and(|abi| abi != "unknown")
        && !supported_abis.is_some_and(|abis| {
            abis.iter()
                .filter_map(Value::as_str)
                .any(|supported| Some(supported) == target_abi)
        })
    {
        *rejected = true;
        reason(
            reasons,
            "target-kernel-abi-conflict",
            "kernel does not declare support for the target userspace ABI",
        );
    }
    let page_status = target
        .pointer("/memory/page_size_sensitivity/status")
        .and_then(Value::as_str);
    let required_page = match page_status {
        Some("tested-4k" | "suspected-4k") => Some("4k"),
        Some("tested-16k" | "suspected-16k") => Some("16k"),
        _ => None,
    };
    let kernel_page = kernel.pointer("/page_size").and_then(Value::as_str);
    if required_page.is_some() && kernel_page != required_page {
        *rejected = true;
        reason(
            reasons,
            "target-kernel-page-size-conflict",
            "kernel page size conflicts with measured target sensitivity",
        );
    }
    if target
        .pointer("/module_dependence/status")
        .and_then(Value::as_str)
        == Some("required-modules-identified")
        && candidate.kernel_build_profile["body"]["support_tier"].as_str()
            != Some("external-required")
    {
        *rejected = true;
        reason(
            reasons,
            "required-modules-generic-kernel",
            "target requires identified binary modules that a generic kernel cannot satisfy",
        );
    }
}

fn evaluate_machine_mappings(
    request: &SelectionRequest,
    candidate: &SelectionCandidate,
    reasons: &mut Vec<SelectionReason>,
    rejected: &mut bool,
) {
    let machine_capabilities = string_set(&candidate.machine_profile["body"]["capabilities"]);
    for requirement in
        string_set(&candidate.kernel_build_profile["body"]["required_machine_capabilities"])
    {
        let mapped = request
            .capability_mappings
            .iter()
            .filter(|mapping| mapping.kernel_requirement == requirement)
            .any(|mapping| machine_capabilities.contains(&mapping.machine_capability));
        if !mapped {
            *rejected = true;
            reason(
                reasons,
                "machine-capability-mapping-missing",
                format!("no satisfied typed machine mapping for kernel requirement {requirement}"),
            );
        }
    }
}

fn evaluate_prohibited_interventions(
    request: &SelectionRequest,
    candidate: &SelectionCandidate,
    reasons: &mut Vec<SelectionReason>,
    rejected: &mut bool,
) {
    let prohibited = string_set(&request.goal_profile["body"]["prohibited_interventions"]);
    let actions = candidate.guest_contract["body"]["adaptations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|adaptation| adaptation.get("action").and_then(Value::as_str));
    for action in actions {
        if prohibited.contains(action) {
            *rejected = true;
            let rationale = request.goal_profile["body"]["prohibited_intervention_rationale"]
                .get(action)
                .and_then(Value::as_str)
                .unwrap_or("goal prohibits this intervention");
            reason(
                reasons,
                "goal-prohibited-intervention",
                format!("{action}: {rationale}"),
            );
        }
    }
}

fn evaluate_negative_evidence(
    request: &SelectionRequest,
    candidate: &SelectionCandidate,
    reasons: &mut Vec<SelectionReason>,
    rejected: &mut bool,
) -> i64 {
    let target_id = request.target_requirement["body"]["target_id"].as_str();
    let mut penalty = 0;
    for negative in request.negative_evidence.iter().filter(|negative| {
        negative.body.candidate_id == candidate.candidate_id
            && Some(negative.body.target_id.as_str()) == target_id
    }) {
        let fields = &negative.body.retest_when.digest_fields;
        if !negative_fields_valid(&negative.body) {
            *rejected = true;
            reason(
                reasons,
                "negative-evidence-binding-incomplete",
                format!(
                    "negative evidence {} does not bind the required owning-layer fields",
                    negative.id
                ),
            );
            continue;
        }
        let active = fields.iter().all(|field| {
            negative.body.tested_binding.get(field)
                == current_binding_value(request, candidate, field).as_ref()
        });
        if !active {
            reason(
                reasons,
                "negative-evidence-expired",
                format!(
                    "negative evidence {} expired after a bound input changed",
                    negative.id
                ),
            );
            continue;
        }
        match negative.body.cause_status.as_str() {
            "observed" => {
                *rejected = true;
                reason(
                    reasons,
                    "observed-negative-evidence-active",
                    format!(
                        "observed failure {} remains active for {}",
                        negative.body.failed_predicate, negative.body.evidence_experiment_id
                    ),
                );
            }
            "inferred" => {
                penalty += 100;
                reason(
                    reasons,
                    "inferred-negative-evidence-active",
                    format!(
                        "inferred failure {} demotes this candidate",
                        negative.body.failed_predicate
                    ),
                );
            }
            _ => {
                penalty += 50;
                reason(
                    reasons,
                    "unknown-negative-evidence-active",
                    "unknown-cause negative evidence conservatively demotes this candidate",
                );
            }
        }
    }
    penalty
}

fn validate_negative_evidence(negative: &NegativeEvidenceRecord) -> Vec<ExperimentValidationError> {
    let mut errors = Vec::new();
    let body_value = serde_json::to_value(&negative.body)
        .expect("negative evidence body serialization cannot fail");
    let actual = canonical_record_digest(&body_value);
    if negative.record_digest != actual {
        errors.push(ExperimentValidationError {
            code: "negative-content-digest-mismatch",
            path: "record_digest".to_string(),
            message: format!("negative evidence digest must be {actual}"),
        });
    }
    let expected_id = format!("neg-{}", &actual["sha256:".len()..][..16]);
    if negative.id != expected_id {
        errors.push(ExperimentValidationError {
            code: "negative-id-digest-mismatch",
            path: "id".to_string(),
            message: format!("negative evidence ID must be {expected_id}"),
        });
    }
    if !matches!(
        negative.body.cause_status.as_str(),
        "observed" | "inferred" | "unknown"
    ) {
        errors.push(ExperimentValidationError {
            code: "negative-cause-status-invalid",
            path: "body.cause_status".to_string(),
            message: "negative cause status must be observed, inferred, or unknown".to_string(),
        });
    }
    if !negative
        .body
        .evidence_experiment_id
        .strip_prefix("exp-")
        .is_some_and(|hex| {
            hex.len() == 16
                && hex
                    .bytes()
                    .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        })
    {
        errors.push(ExperimentValidationError {
            code: "negative-experiment-id-invalid",
            path: "body.evidence_experiment_id".to_string(),
            message: "negative evidence must reference a canonical experiment ID".to_string(),
        });
    }
    if negative.body.failed_predicate.trim().is_empty()
        || negative.body.candidate_id.trim().is_empty()
        || negative.body.target_id.trim().is_empty()
    {
        errors.push(ExperimentValidationError {
            code: "negative-identity-field-missing",
            path: "body".to_string(),
            message: "candidate, target, and failed predicate must be non-empty".to_string(),
        });
    }
    if negative
        .body
        .tested_binding
        .values()
        .any(|value| value.starts_with("sha256:") && !is_sha256_digest(value))
    {
        errors.push(ExperimentValidationError {
            code: "negative-binding-digest-invalid",
            path: "body.tested_binding".to_string(),
            message: "tested SHA-256 bindings must use canonical lowercase digests".to_string(),
        });
    }
    if !negative_fields_valid(&negative.body) {
        errors.push(ExperimentValidationError {
            code: "negative-evidence-binding-incomplete",
            path: "body.retest_when".to_string(),
            message:
                "negative evidence must bind every owning-layer field named by its retest policy"
                    .to_string(),
        });
    }
    errors
}

fn negative_fields_valid(negative: &NegativeEvidenceBody) -> bool {
    const ALL_STABLE_FIELDS: &[&str] = &[
        "bindings.target_requirement.input_digest",
        "bindings.machine_profile.fat_profile_revision",
        "bindings.machine_profile.qemu_binary_digest",
        "bindings.kernel_build_profile.kernel_artifact_digest",
        "bindings.guest_contract.rootfs_artifact_digest",
        "bindings.goal_profile.record_digest",
    ];
    let allowed_prefix = match negative.retest_when.owning_layer.as_str() {
        "target-requirements" => Some("bindings.target_requirement."),
        "machine" => Some("bindings.machine_profile."),
        "kernel" => Some("bindings.kernel_build_profile."),
        "guest-contract" => Some("bindings.guest_contract."),
        "goal" => Some("bindings.goal_profile."),
        "unknown" => None,
        _ => return false,
    };
    let fields = negative
        .retest_when
        .digest_fields
        .iter()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if negative.retest_when.owning_layer == "unknown"
        && !ALL_STABLE_FIELDS.iter().all(|field| fields.contains(field))
    {
        return false;
    }
    if let Some(prefix) = allowed_prefix {
        if fields.is_empty() || fields.iter().any(|field| !field.starts_with(prefix)) {
            return false;
        }
    }
    fields
        .iter()
        .all(|field| negative.tested_binding.contains_key(*field))
}

fn current_binding_value(
    request: &SelectionRequest,
    candidate: &SelectionCandidate,
    field: &str,
) -> Option<String> {
    let value = match field {
        "bindings.target_requirement.record_digest" => {
            request.target_requirement.pointer("/record_digest")
        }
        "bindings.target_requirement.input_digest" => {
            request.target_requirement.pointer("/body/firmware_digest")
        }
        "bindings.machine_profile.record_digest" => {
            candidate.machine_profile.pointer("/record_digest")
        }
        "bindings.machine_profile.fat_profile_revision" => candidate
            .machine_profile
            .pointer("/body/fat_profile_revision"),
        "bindings.machine_profile.qemu_binary_digest" => candidate
            .machine_profile
            .pointer("/body/qemu/binary_digest"),
        "bindings.kernel_build_profile.record_digest" => {
            candidate.kernel_build_profile.pointer("/record_digest")
        }
        "bindings.kernel_build_profile.kernel_artifact_digest" => candidate
            .kernel_build_profile
            .pointer("/body/artifact_digest"),
        "bindings.guest_contract.record_digest" => {
            candidate.guest_contract.pointer("/record_digest")
        }
        "bindings.guest_contract.rootfs_artifact_digest" => candidate
            .guest_contract
            .pointer("/body/assembled_rootfs_digest"),
        "bindings.goal_profile.record_digest" => request.goal_profile.pointer("/record_digest"),
        _ => None,
    };
    value.and_then(Value::as_str).map(str::to_string)
}

fn target_has_unresolved_hard_facts(target: &Value) -> bool {
    let body = &target["body"];
    let listed = body["unresolved_hard_facts"]
        .as_array()
        .is_some_and(|facts| !facts.is_empty());
    listed
        || ["/cpu/isa_floor", "/cpu/endianness", "/userspace_abi/abi"]
            .iter()
            .any(|pointer| body.pointer(pointer).and_then(Value::as_str) == Some("unknown"))
        || body
            .pointer("/memory/page_size_sensitivity/status")
            .and_then(Value::as_str)
            == Some("unknown")
}

fn matching_prior_exact(request: &SelectionRequest, candidate: &SelectionCandidate) -> bool {
    request.prior_experiments.iter().any(|experiment| {
        experiment.experiment.record_status.as_deref() == Some("finalized")
            && matches!(
                experiment.experiment.verdict.compatibility.as_str(),
                "partial" | "supported"
            )
            && binding_id(&experiment.bound_records["target_requirement"])
                == binding_id(&request.target_requirement)
            && binding_id(&experiment.bound_records["goal_profile"])
                == binding_id(&request.goal_profile)
            && binding_id(&experiment.bound_records["machine_profile"])
                == binding_id(&candidate.machine_profile)
            && binding_id(&experiment.bound_records["kernel_build_profile"])
                == binding_id(&candidate.kernel_build_profile)
            && binding_id(&experiment.bound_records["guest_contract"])
                == binding_id(&candidate.guest_contract)
    })
}

fn matching_prior_depth(request: &SelectionRequest, candidate: &SelectionCandidate) -> usize {
    request
        .prior_experiments
        .iter()
        .filter(|experiment| {
            experiment.experiment.record_status.as_deref() == Some("finalized")
                && matches!(
                    experiment.experiment.verdict.compatibility.as_str(),
                    "partial" | "supported"
                )
                && binding_id(&experiment.bound_records["target_requirement"])
                    == binding_id(&request.target_requirement)
                && binding_id(&experiment.bound_records["goal_profile"])
                    == binding_id(&request.goal_profile)
                && binding_id(&experiment.bound_records["machine_profile"])
                    == binding_id(&candidate.machine_profile)
                && binding_id(&experiment.bound_records["kernel_build_profile"])
                    == binding_id(&candidate.kernel_build_profile)
                && binding_id(&experiment.bound_records["guest_contract"])
                    == binding_id(&candidate.guest_contract)
        })
        .map(|experiment| experiment.experiment.proof_ladder.reached_predicates.len())
        .max()
        .unwrap_or(0)
}

fn binding_id(record: &Value) -> Option<&str> {
    record.get("id").and_then(Value::as_str)
}

fn guest_semantic_risk(guest: &Value) -> i64 {
    guest["body"]["adaptations"]
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(|adaptation| adaptation.get("semantic_risk").and_then(Value::as_str))
        .map(|risk| match risk {
            "low" => 1,
            "medium" => 5,
            "medium-high" => 10,
            "high" => 25,
            "very-high" => 50,
            _ => 100,
        })
        .sum()
}

fn string_set(value: &Value) -> BTreeSet<String> {
    value
        .as_array()
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_string)
        .collect()
}

fn reason(reasons: &mut Vec<SelectionReason>, code: impl Into<String>, message: impl Into<String>) {
    reasons.push(SelectionReason {
        code: code.into(),
        message: message.into(),
    });
}

fn best_candidate(
    decisions: &[CandidateDecision],
    disposition: CandidateDisposition,
) -> Option<&CandidateDecision> {
    decisions
        .iter()
        .filter(|decision| decision.disposition == disposition)
        .max_by(|left, right| {
            left.score
                .cmp(&right.score)
                .then_with(|| right.candidate_id.cmp(&left.candidate_id))
        })
}
