use std::collections::{BTreeMap, BTreeSet};

use fat_core::rehosting::{RehostingMode, TargetExecutionProfile};
use fat_core::rehosting_policy::SubstrateKind as LogicalSubstrateKind;
use fat_core::target_model::{
    ModelServiceCandidate, ServiceExecutionClass, TargetModel, TargetModelInitCandidate,
    TargetModelNetworkHypothesis, TargetModelNvramFact,
};
use fat_family::classify;

pub(crate) const PROFILE_PROJECT_ID: &str = "emulation-project";
pub(crate) const PROFILE_TARGET_ID: &str = "emulation-target";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetProfileRequest {
    pub project_id: String,
    pub target_id: String,
    pub evidence: Vec<String>,
}

pub fn build_target_model(request: &TargetProfileRequest) -> TargetModel {
    let family_guess = classify(request.evidence.iter().map(|signal| signal.as_str()));
    let family_id = Some(family_guess.family_id);
    let architecture = request
        .evidence
        .iter()
        .find_map(|signal| signal.strip_prefix("arch:"))
        .map(str::to_string);

    TargetModel::new(
        request.project_id.clone(),
        request.target_id.clone(),
        architecture.as_deref(),
        family_id.as_deref(),
        request.evidence.clone(),
    )
    .with_init_candidates(collect_init_candidates(request.evidence.as_slice()))
    .with_service_candidates(collect_service_candidates(request.evidence.as_slice()))
    .with_network_hypotheses(collect_network_hypotheses(request.evidence.as_slice()))
    .with_nvram_facts(collect_nvram_facts(request.evidence.as_slice()))
    .with_substrate_viability_hints(collect_substrate_viability_hints(
        request.evidence.as_slice(),
        family_id.as_deref(),
    ))
}

pub fn build_target_profile(request: &TargetProfileRequest) -> TargetExecutionProfile {
    build_target_model(request).to_execution_profile()
}

pub fn readiness_goals_for_profile(profile: &TargetExecutionProfile) -> Vec<String> {
    let mut goals = vec!["shell-access".to_string()];

    if profile.candidate_modes.contains(&RehostingMode::Service) {
        push_unique(&mut goals, "listener-bind");
        push_unique(&mut goals, "http-validation");
        push_unique(&mut goals, "process-chain");
    }
    if profile.candidate_modes.contains(&RehostingMode::System) {
        push_unique(&mut goals, "process-chain");
        push_unique(&mut goals, "init-complete");
    }
    if profile.candidate_modes.contains(&RehostingMode::Reference) {
        push_unique(&mut goals, "reference-bootstrap");
    }

    goals
}

pub fn readiness_goal_signature(goals: &[String]) -> String {
    goals.join("|")
}

pub fn profile_context_entries(profile: &TargetExecutionProfile) -> Vec<String> {
    let mut entries = vec![format!("profile={}", profile.profile_id)];

    if let Some(family_id) = profile.family_id.as_deref() {
        push_unique_owned(&mut entries, format!("family={family_id}"));
    }
    if let Some(architecture) = profile.architecture.as_deref() {
        push_unique_owned(&mut entries, format!("arch={architecture}"));
    }
    for mode in &profile.candidate_modes {
        push_unique_owned(&mut entries, format!("mode={}", mode.as_str()));
    }

    entries
}

pub fn readiness_goal_debug_features(goals: &[String]) -> Vec<String> {
    let mut features = Vec::new();
    for goal in goals {
        push_unique_owned(&mut features, format!("goal={goal}"));
    }
    features
}

pub fn logical_substrate_for_profile(
    profile: &TargetExecutionProfile,
    backend_id: &str,
) -> LogicalSubstrateKind {
    match backend_id {
        "emux" => LogicalSubstrateKind::Reference,
        "firmae" | "firmadyne" => LogicalSubstrateKind::System,
        _ if profile.candidate_modes.contains(&RehostingMode::System) => {
            LogicalSubstrateKind::System
        }
        _ if profile.candidate_modes.contains(&RehostingMode::Reference) => {
            LogicalSubstrateKind::Reference
        }
        _ => LogicalSubstrateKind::Service,
    }
}

fn collect_unique_hints(evidence: &[String], prefixes: &[&str]) -> Vec<String> {
    let mut hints = BTreeSet::new();

    for signal in evidence {
        for prefix in prefixes {
            if let Some(value) = signal.strip_prefix(prefix) {
                hints.insert(value.to_string());
                break;
            }
        }
    }

    hints.into_iter().collect()
}

fn collect_init_candidates(evidence: &[String]) -> Vec<TargetModelInitCandidate> {
    let mut candidates = BTreeMap::new();
    for path in collect_unique_hints(evidence, &["init:"]) {
        candidates.insert(path.clone(), init_candidate_confidence(&path));
    }

    let mut candidates = candidates
        .into_iter()
        .map(|(path, confidence)| TargetModelInitCandidate::new(path, confidence))
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        right
            .confidence
            .cmp(&left.confidence)
            .then(left.path.cmp(&right.path))
    });
    candidates
}

fn collect_service_candidates(evidence: &[String]) -> Vec<ModelServiceCandidate> {
    let mut candidates = Vec::new();
    for signal in evidence {
        if let Some(path) = signal.strip_prefix("service:") {
            candidates.push(ModelServiceCandidate::new(
                path.to_string(),
                ServiceExecutionClass::Standalone,
            ));
        } else if let Some(path) = signal.strip_prefix("web:cgi") {
            let normalized = normalize_cgi_candidate(path);
            candidates.push(ModelServiceCandidate::new(
                normalized,
                ServiceExecutionClass::Standalone,
            ));
        } else if signal.starts_with("web:httpd") {
            candidates.push(ModelServiceCandidate::new(
                "/usr/sbin/httpd",
                ServiceExecutionClass::Standalone,
            ));
        } else if signal.starts_with("web:uhttpd") {
            candidates.push(ModelServiceCandidate::new(
                "/usr/sbin/uhttpd",
                ServiceExecutionClass::Standalone,
            ));
        }
    }
    dedupe_service_candidates(candidates)
}

fn collect_network_hypotheses(evidence: &[String]) -> Vec<TargetModelNetworkHypothesis> {
    let mut hypotheses = Vec::new();
    for signal in evidence {
        if let Some(interface_name) = signal.strip_prefix("iface:") {
            hypotheses.push(TargetModelNetworkHypothesis::new(
                interface_name,
                "interface",
            ));
        } else if let Some(interface_name) = signal.strip_prefix("bridge:") {
            hypotheses.push(TargetModelNetworkHypothesis::new(interface_name, "bridge"));
        } else if let Some(seed) = signal.strip_prefix("ip:") {
            if let Some((interface_name, cidr)) = seed.split_once('=') {
                hypotheses.push(TargetModelNetworkHypothesis::new(
                    interface_name,
                    format!("seed-ip:{cidr}"),
                ));
            }
        } else if let Some(bind_target) = signal.strip_prefix("bind:") {
            hypotheses.push(TargetModelNetworkHypothesis::new(
                bind_target,
                "bind-target",
            ));
        }
    }
    hypotheses.sort_by(|left, right| {
        left.interface_name
            .cmp(&right.interface_name)
            .then(left.role.cmp(&right.role))
    });
    hypotheses
}

fn collect_nvram_facts(evidence: &[String]) -> Vec<TargetModelNvramFact> {
    let mut facts = BTreeMap::new();

    for signal in evidence {
        let (raw_key, resolution_state) =
            if let Some(raw_key) = signal.strip_prefix("nvram-override:") {
                (raw_key, "overridden")
            } else if let Some(raw_key) = signal.strip_prefix("nvram-observed:") {
                (raw_key, "observed")
            } else if let Some(raw_key) = signal.strip_prefix("nvram-default:") {
                (raw_key, "synthesized")
            } else if let Some(raw_key) = signal.strip_prefix("nvram:") {
                (raw_key, "missing")
            } else {
                continue;
            };
        let key = raw_key
            .split_once('=')
            .map(|(key, _)| key)
            .unwrap_or(raw_key)
            .trim();
        if key.is_empty() {
            continue;
        }

        facts
            .entry(key.to_string())
            .or_insert_with(|| resolution_state.to_string());
        if resolution_state == "overridden" || resolution_state == "observed" {
            facts.insert(key.to_string(), resolution_state.to_string());
        }
    }

    facts
        .into_iter()
        .map(|(key, resolution_state)| TargetModelNvramFact::new(key, resolution_state))
        .collect()
}

fn collect_substrate_viability_hints(evidence: &[String], family_id: Option<&str>) -> Vec<String> {
    let mut hints = Vec::new();
    if evidence.iter().any(|signal| is_reference_evidence(signal)) {
        hints.push("reference:available".to_string());
    }
    if family_id
        .map(|family| family.starts_with("linux-router-"))
        .unwrap_or(false)
        && evidence.iter().any(|signal| signal.starts_with("init:"))
    {
        hints.push("system:init-present".to_string());
    }
    if evidence.iter().any(|signal| is_service_evidence(signal)) {
        hints.push("service:web-entrypoint".to_string());
    }
    hints
}

fn is_service_evidence(signal: &str) -> bool {
    matches!(
        signal,
        value if value.starts_with("web:cgi")
            || value.starts_with("web:httpd")
            || value.starts_with("web:uhttpd")
            || value.starts_with("service:")
    )
}

fn is_reference_evidence(signal: &str) -> bool {
    signal.starts_with("reference:")
        || signal.starts_with("generated:reference")
        || signal.starts_with("emux:")
}

fn init_candidate_confidence(path: &str) -> u8 {
    if path.contains("preinit") {
        130
    } else if path.ends_with("rcS") {
        120
    } else if path == "/sbin/init" || path.ends_with("/init") {
        110
    } else {
        100
    }
}

fn push_unique(values: &mut Vec<String>, value: &str) {
    if !values.iter().any(|existing| existing == value) {
        values.push(value.to_string());
    }
}

fn push_unique_owned(values: &mut Vec<String>, value: String) {
    if !values.contains(&value) {
        values.push(value);
    }
}

fn dedupe_service_candidates(candidates: Vec<ModelServiceCandidate>) -> Vec<ModelServiceCandidate> {
    let mut deduped = Vec::new();
    for candidate in candidates {
        if !deduped
            .iter()
            .any(|existing: &ModelServiceCandidate| existing.path == candidate.path)
        {
            deduped.push(candidate);
        }
    }
    deduped
}

fn normalize_cgi_candidate(path: &str) -> String {
    let trimmed = path.trim_start_matches(':');
    if trimmed.is_empty() {
        "/cgi-bin".to_string()
    } else if trimmed.starts_with('/') {
        trimmed.to_string()
    } else {
        format!("/{trimmed}")
    }
}
