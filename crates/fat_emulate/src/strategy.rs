use std::collections::HashMap;

use fat_backend::{
    logical_substrate_for_backend, logical_substrates_for_backend_id, BackendRegistry,
    BackendSubstrateKind,
};
use fat_core::rehosting_policy::{SubstrateKind as LogicalSubstrateKind, SubstratePreference};
use fat_core::runs::SubstrateKind;
use fat_family::classify;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmulationAutomationMode {
    SuggestOnly,
    AutoSafe,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PriorRunSummary {
    pub run_id: String,
    pub backend_id: String,
    pub substrate: String,
    pub status: String,
}

impl PriorRunSummary {
    pub fn new(
        run_id: impl Into<String>,
        backend_id: impl Into<String>,
        substrate: impl Into<String>,
        status: impl Into<String>,
    ) -> Self {
        Self {
            run_id: run_id.into(),
            backend_id: backend_id.into(),
            substrate: substrate.into(),
            status: status.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StrategyRequest {
    pub goal: String,
    pub target_evidence: Vec<String>,
    pub host_capabilities: Vec<String>,
    pub prior_runs: Vec<PriorRunSummary>,
    pub substrate_preference: SubstratePreference,
    pub automation_mode: EmulationAutomationMode,
    pub requested_backend: Option<String>,
    pub requested_substrate: Option<String>,
}

impl StrategyRequest {
    pub fn new(
        goal: impl Into<String>,
        target_evidence: Vec<String>,
        host_capabilities: Vec<String>,
        prior_runs: Vec<PriorRunSummary>,
    ) -> Self {
        Self {
            goal: goal.into(),
            target_evidence,
            host_capabilities,
            prior_runs,
            substrate_preference: SubstratePreference::Auto,
            automation_mode: EmulationAutomationMode::SuggestOnly,
            requested_backend: None,
            requested_substrate: None,
        }
    }

    pub fn with_automation_mode(mut self, automation_mode: EmulationAutomationMode) -> Self {
        self.automation_mode = automation_mode;
        self
    }

    pub fn with_requested_backend(mut self, backend_id: impl Into<String>) -> Self {
        self.requested_backend = Some(backend_id.into());
        self
    }

    pub fn with_requested_substrate(mut self, substrate: impl Into<String>) -> Self {
        self.requested_substrate = Some(substrate.into());
        self
    }

    pub fn with_substrate_preference(mut self, substrate_preference: SubstratePreference) -> Self {
        self.substrate_preference = substrate_preference;
        self
    }
}

#[derive(Debug, Clone, PartialEq)]
pub struct StrategyCandidate {
    pub backend_id: String,
    pub display_name: String,
    pub substrate: SubstrateKind,
    pub logical_substrate: LogicalSubstrateKind,
    pub family_id: String,
    pub score: f32,
    pub rationale: Vec<String>,
    pub hard_constraint_reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StrategyRejectedCandidate {
    pub backend_id: String,
    pub display_name: String,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct StrategyEvaluation {
    pub request: StrategyRequest,
    pub family_id: String,
    pub family_confidence_percent: u8,
    pub candidates: Vec<StrategyCandidate>,
    pub filtered_out: Vec<StrategyRejectedCandidate>,
    pub selected: StrategyCandidate,
    pub reasoning: Vec<String>,
}

pub type StrategySelection = StrategyEvaluation;

#[derive(Debug)]
pub struct StrategyEngine {
    registry: BackendRegistry,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StrategyError {
    RequestedBackendUnavailable { backend_id: String },
    NoViableCandidates { goal: String, family_id: String },
}

impl StrategyEngine {
    pub fn new(registry: BackendRegistry) -> Self {
        Self { registry }
    }

    pub fn evaluate(&self, request: &StrategyRequest) -> Result<StrategyEvaluation, StrategyError> {
        let family_guess = classify(request.target_evidence.iter().map(|signal| signal.as_str()));
        let family_id = family_guess.family_id.clone();
        let family_confidence_percent = (family_guess.confidence * 100.0).round() as u8;

        if let Some(requested_backend) = request.requested_backend.as_deref() {
            let known_backend = self
                .registry
                .driver_contracts()
                .iter()
                .any(|contract| contract.backend_id == requested_backend);
            if !known_backend {
                return Err(StrategyError::RequestedBackendUnavailable {
                    backend_id: requested_backend.to_string(),
                });
            }
        }

        let family_scores: HashMap<String, (f32, String)> = self
            .registry
            .rank_family(&family_id)
            .into_iter()
            .map(|score| (score.backend_id, (score.score, score.rationale)))
            .collect();

        let mut eligible = Vec::new();
        let mut filtered_out = Vec::new();

        for contract in self.registry.driver_contracts() {
            let mut hard_reasons = Vec::new();

            if let Some(requested_backend) = request.requested_backend.as_deref() {
                if requested_backend != contract.backend_id {
                    filtered_out.push(StrategyRejectedCandidate {
                        backend_id: contract.backend_id.clone(),
                        display_name: contract.display_name.clone(),
                        reasons: vec![format!(
                            "requested backend {requested_backend} does not match {}",
                            contract.backend_id
                        )],
                    });
                    continue;
                }
                hard_reasons.push(format!(
                    "explicit backend request for {}",
                    contract.backend_id
                ));
            }

            let substrate = if let Some(requested_substrate) =
                request.requested_substrate.as_deref()
            {
                let requested_substrate =
                    substrate_kind_from_label(requested_substrate).map_err(|_| {
                        StrategyError::NoViableCandidates {
                            goal: request.goal.clone(),
                            family_id: family_id.clone(),
                        }
                    })?;
                if request.requested_backend.is_some() {
                    if !contract.supported_substrates.iter().any(|candidate| {
                        backend_substrate_to_runtime(*candidate) == requested_substrate
                    }) {
                        filtered_out.push(StrategyRejectedCandidate {
                            backend_id: contract.backend_id.clone(),
                            display_name: contract.display_name.clone(),
                            reasons: vec![format!(
                                "backend {} does not support requested substrate {}",
                                contract.backend_id,
                                requested_substrate.as_str()
                            )],
                        });
                        continue;
                    }
                    if !host_capability_allows(&request.host_capabilities, requested_substrate) {
                        filtered_out.push(StrategyRejectedCandidate {
                            backend_id: contract.backend_id.clone(),
                            display_name: contract.display_name.clone(),
                            reasons: vec![format!(
                                "missing host capability {}",
                                requested_substrate.as_str()
                            )],
                        });
                        continue;
                    }
                    hard_reasons.push(format!(
                        "compatibility substrate override {}",
                        requested_substrate.as_str()
                    ));
                    requested_substrate
                } else if contract.supported_substrates.iter().any(|candidate| {
                    backend_substrate_to_runtime(*candidate) == requested_substrate
                }) {
                    if !host_capability_allows(&request.host_capabilities, requested_substrate) {
                        filtered_out.push(StrategyRejectedCandidate {
                            backend_id: contract.backend_id,
                            display_name: contract.display_name,
                            reasons: vec![format!(
                                "missing host capability {}",
                                requested_substrate.as_str()
                            )],
                        });
                        continue;
                    }
                    hard_reasons.push(format!(
                        "requested substrate {}",
                        requested_substrate.as_str()
                    ));
                    requested_substrate
                } else {
                    filtered_out.push(StrategyRejectedCandidate {
                        backend_id: contract.backend_id.clone(),
                        display_name: contract.display_name.clone(),
                        reasons: vec![format!(
                            "unsupported requested substrate {}",
                            requested_substrate.as_str()
                        )],
                    });
                    continue;
                }
            } else if let Some(candidate_substrate) = contract.substrates.iter().find(|substrate| {
                host_capability_allows(
                    &request.host_capabilities,
                    backend_substrate_to_runtime(substrate.kind),
                )
            }) {
                let substrate = backend_substrate_to_runtime(candidate_substrate.kind);
                hard_reasons.push(format!(
                    "host capability {} matched substrate {}",
                    substrate.as_str(),
                    substrate.as_str()
                ));
                substrate
            } else {
                filtered_out.push(StrategyRejectedCandidate {
                    backend_id: contract.backend_id.clone(),
                    display_name: contract.display_name.clone(),
                    reasons: vec!["no supported substrate matched host capabilities".to_string()],
                });
                continue;
            };

            let logical_substrate = preferred_logical_substrate_for_candidate(
                contract.backend_id.as_str(),
                request.requested_backend.is_some(),
                request.substrate_preference,
                &request.target_evidence,
            );
            if request.substrate_preference == SubstratePreference::ReferenceOnly
                && logical_substrate != LogicalSubstrateKind::Reference
            {
                filtered_out.push(StrategyRejectedCandidate {
                    backend_id: contract.backend_id.clone(),
                    display_name: contract.display_name.clone(),
                    reasons: vec!["preference requires reference substrate".to_string()],
                });
                continue;
            }

            if request.requested_backend.is_none() {
                let allowed_substrates: Vec<String> = contract
                    .supported_substrates
                    .iter()
                    .map(|substrate| backend_substrate_label(*substrate).to_string())
                    .collect();
                if !allowed_substrates.contains(&substrate.as_str().to_string()) {
                    filtered_out.push(StrategyRejectedCandidate {
                        backend_id: contract.backend_id.clone(),
                        display_name: contract.display_name.clone(),
                        reasons: vec![format!(
                            "backend {} does not support substrate {}",
                            contract.backend_id,
                            substrate.as_str()
                        )],
                    });
                    continue;
                }
            }

            let (score, score_rationale) = family_scores
                .get(&contract.backend_id)
                .cloned()
                .unwrap_or_else(|| {
                    if request.requested_backend.as_deref() == Some(contract.backend_id.as_str()) {
                        (
                            1.0,
                            "explicit backend request selected this backend".to_string(),
                        )
                    } else {
                        (0.0, "no family score available".to_string())
                    }
                });

            let mut rationale = vec![score_rationale];
            rationale.push(format!("selected substrate {}", substrate.as_str()));
            rationale.push(format!(
                "logical substrate {} under preference {}",
                logical_substrate.as_str(),
                request.substrate_preference.as_str()
            ));
            if request.requested_backend.as_deref() == Some(contract.backend_id.as_str()) {
                rationale.push(format!(
                    "explicit backend request for {}",
                    contract.backend_id
                ));
            }

            eligible.push(StrategyCandidate {
                backend_id: contract.backend_id.clone(),
                display_name: contract.display_name.clone(),
                substrate,
                logical_substrate,
                family_id: family_id.clone(),
                score,
                rationale,
                hard_constraint_reasons: hard_reasons,
            });
        }

        if eligible.is_empty() {
            return Err(StrategyError::NoViableCandidates {
                goal: request.goal.clone(),
                family_id,
            });
        }

        let gated_logical_substrate = if request.requested_backend.is_none() {
            request
                .substrate_preference
                .default_order()
                .into_iter()
                .find(|substrate| {
                    eligible
                        .iter()
                        .any(|candidate| candidate.logical_substrate == *substrate)
                })
        } else {
            None
        };

        if let Some(gated_logical_substrate) = gated_logical_substrate {
            let mut retained = Vec::new();
            for candidate in eligible {
                if candidate.logical_substrate == gated_logical_substrate {
                    retained.push(candidate);
                } else {
                    filtered_out.push(StrategyRejectedCandidate {
                        backend_id: candidate.backend_id,
                        display_name: candidate.display_name,
                        reasons: vec![format!(
                            "lower-priority logical substrate than {}",
                            gated_logical_substrate.as_str()
                        )],
                    });
                }
            }
            eligible = retained;
        }

        eligible.sort_by(|left, right| {
            right
                .score
                .partial_cmp(&left.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| left.backend_id.cmp(&right.backend_id))
        });

        let selected = eligible[0].clone();
        let mut reasoning = vec![format!(
            "family {} confidence {}%",
            selected.family_id, family_confidence_percent
        )];
        if let Some(gated_logical_substrate) = gated_logical_substrate {
            reasoning.push(format!(
                "logical substrate gate selected {}",
                gated_logical_substrate.as_str()
            ));
        }
        if !request.target_evidence.is_empty() {
            reasoning.push(format!(
                "target evidence: {}",
                request.target_evidence.join(", ")
            ));
        }
        if !request.prior_runs.is_empty() {
            reasoning.push(format!(
                "prior runs considered: {}",
                request.prior_runs.len()
            ));
            reasoning.extend(request.prior_runs.iter().map(|prior_run| {
                format!(
                    "prior run {} on {} via {} ({})",
                    prior_run.run_id, prior_run.backend_id, prior_run.substrate, prior_run.status
                )
            }));
        }
        reasoning.extend(selected.rationale.iter().cloned());
        reasoning.extend(selected.hard_constraint_reasons.iter().cloned());

        Ok(StrategyEvaluation {
            request: request.clone(),
            family_id,
            family_confidence_percent,
            candidates: eligible,
            filtered_out,
            selected,
            reasoning,
        })
    }

    pub fn select(&self, request: StrategyRequest) -> Result<StrategySelection, StrategyError> {
        self.evaluate(&request)
    }
}

fn preferred_logical_substrate_for_candidate(
    backend_id: &str,
    explicit_backend_request: bool,
    substrate_preference: SubstratePreference,
    target_evidence: &[String],
) -> LogicalSubstrateKind {
    if !explicit_backend_request || substrate_preference == SubstratePreference::Auto {
        return logical_substrate_for_backend(backend_id, target_evidence);
    }

    substrate_preference
        .default_order()
        .into_iter()
        .find(|substrate| logical_substrates_for_backend_id(backend_id).contains(substrate))
        .unwrap_or_else(|| logical_substrate_for_backend(backend_id, target_evidence))
}

fn host_capability_allows(host_capabilities: &[String], substrate: SubstrateKind) -> bool {
    host_capabilities
        .iter()
        .any(|capability| capability == substrate.as_str())
}

fn substrate_kind_from_label(label: &str) -> Result<SubstrateKind, ()> {
    match label {
        "native-host" => Ok(SubstrateKind::NativeHost),
        "docker-engine" => Ok(SubstrateKind::DockerEngine),
        "managed-linux-vm" => Ok(SubstrateKind::ManagedLinuxVm),
        _ => Err(()),
    }
}

fn backend_substrate_label(substrate: BackendSubstrateKind) -> &'static str {
    match substrate {
        BackendSubstrateKind::NativeHost => "native-host",
        BackendSubstrateKind::DockerEngine => "docker-engine",
        BackendSubstrateKind::ManagedLinuxVm => "managed-linux-vm",
    }
}

fn backend_substrate_to_runtime(substrate: BackendSubstrateKind) -> SubstrateKind {
    match substrate {
        BackendSubstrateKind::NativeHost => SubstrateKind::NativeHost,
        BackendSubstrateKind::DockerEngine => SubstrateKind::DockerEngine,
        BackendSubstrateKind::ManagedLinuxVm => SubstrateKind::ManagedLinuxVm,
    }
}
