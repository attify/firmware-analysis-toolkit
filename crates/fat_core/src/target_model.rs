use serde::{Deserialize, Serialize};

use crate::ids::stable_prefixed_id;
use crate::rehosting::{RehostingMode, TargetExecutionProfile};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ServiceExecutionClass {
    Standalone,
    RequiresPeerDaemon,
    KernelCoupled,
    Unsuitable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetModelInitCandidate {
    pub path: String,
    pub confidence: u8,
}

impl TargetModelInitCandidate {
    pub fn new(path: impl Into<String>, confidence: u8) -> Self {
        Self {
            path: path.into(),
            confidence,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelServiceCandidate {
    pub path: String,
    pub execution_class: ServiceExecutionClass,
}

impl ModelServiceCandidate {
    pub fn new(path: impl Into<String>, execution_class: ServiceExecutionClass) -> Self {
        Self {
            path: path.into(),
            execution_class,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetModelNetworkHypothesis {
    pub interface_name: String,
    pub role: String,
}

impl TargetModelNetworkHypothesis {
    pub fn new(interface_name: impl Into<String>, role: impl Into<String>) -> Self {
        Self {
            interface_name: interface_name.into(),
            role: role.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetModelNvramFact {
    pub key: String,
    pub resolution_state: String,
}

impl TargetModelNvramFact {
    pub fn new(key: impl Into<String>, resolution_state: impl Into<String>) -> Self {
        Self {
            key: key.into(),
            resolution_state: resolution_state.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetModel {
    pub model_id: String,
    pub project_id: String,
    pub target_id: String,
    pub architecture: Option<String>,
    pub secondary_arches: Vec<String>,
    pub family_id: Option<String>,
    pub evidence: Vec<String>,
    pub loader_path: Option<String>,
    pub libc_family: Option<String>,
    pub init_candidates: Vec<TargetModelInitCandidate>,
    pub service_candidates: Vec<ModelServiceCandidate>,
    pub peer_dependencies: Vec<String>,
    pub network_hypotheses: Vec<TargetModelNetworkHypothesis>,
    pub nvram_facts: Vec<TargetModelNvramFact>,
    pub device_dependencies: Vec<String>,
    pub ipc_dependencies: Vec<String>,
    pub validator_candidates: Vec<String>,
    pub substrate_viability_hints: Vec<String>,
}

impl TargetModel {
    pub fn new(
        project_id: impl Into<String>,
        target_id: impl Into<String>,
        architecture: Option<&str>,
        family_id: Option<&str>,
        evidence: Vec<String>,
    ) -> Self {
        let project_id = project_id.into();
        let target_id = target_id.into();
        let architecture_value = architecture.map(str::to_string);
        let family_value = family_id.map(str::to_string);
        let mut evidence_signature = evidence.clone();
        evidence_signature.sort();
        let evidence_signature = if evidence_signature.is_empty() {
            "no-evidence".to_string()
        } else {
            evidence_signature.join("|")
        };
        let model_id = stable_prefixed_id(
            "tmodel",
            [
                project_id.as_str(),
                target_id.as_str(),
                architecture.unwrap_or("unknown"),
                family_id.unwrap_or("unknown"),
                evidence_signature.as_str(),
            ],
        );

        Self {
            model_id,
            project_id,
            target_id,
            architecture: architecture_value,
            secondary_arches: Vec::new(),
            family_id: family_value,
            evidence,
            loader_path: None,
            libc_family: None,
            init_candidates: Vec::new(),
            service_candidates: Vec::new(),
            peer_dependencies: Vec::new(),
            network_hypotheses: Vec::new(),
            nvram_facts: Vec::new(),
            device_dependencies: Vec::new(),
            ipc_dependencies: Vec::new(),
            validator_candidates: Vec::new(),
            substrate_viability_hints: Vec::new(),
        }
    }

    pub fn with_secondary_arches(mut self, secondary_arches: Vec<String>) -> Self {
        self.secondary_arches = secondary_arches;
        self
    }

    pub fn with_loader_path(mut self, loader_path: impl Into<String>) -> Self {
        self.loader_path = Some(loader_path.into());
        self
    }

    pub fn with_libc_family(mut self, libc_family: impl Into<String>) -> Self {
        self.libc_family = Some(libc_family.into());
        self
    }

    pub fn with_init_candidates(mut self, init_candidates: Vec<TargetModelInitCandidate>) -> Self {
        self.init_candidates = init_candidates;
        self
    }

    pub fn with_service_candidates(
        mut self,
        service_candidates: Vec<ModelServiceCandidate>,
    ) -> Self {
        self.service_candidates = service_candidates;
        self
    }

    pub fn with_peer_dependencies(mut self, peer_dependencies: Vec<String>) -> Self {
        self.peer_dependencies = peer_dependencies;
        self
    }

    pub fn with_network_hypotheses(
        mut self,
        network_hypotheses: Vec<TargetModelNetworkHypothesis>,
    ) -> Self {
        self.network_hypotheses = network_hypotheses;
        self
    }

    pub fn with_nvram_facts(mut self, nvram_facts: Vec<TargetModelNvramFact>) -> Self {
        self.nvram_facts = nvram_facts;
        self
    }

    pub fn with_device_dependencies(mut self, device_dependencies: Vec<String>) -> Self {
        self.device_dependencies = device_dependencies;
        self
    }

    pub fn with_ipc_dependencies(mut self, ipc_dependencies: Vec<String>) -> Self {
        self.ipc_dependencies = ipc_dependencies;
        self
    }

    pub fn with_validator_candidates(mut self, validator_candidates: Vec<String>) -> Self {
        self.validator_candidates = validator_candidates;
        self
    }

    pub fn with_substrate_viability_hints(
        mut self,
        substrate_viability_hints: Vec<String>,
    ) -> Self {
        self.substrate_viability_hints = substrate_viability_hints;
        self
    }

    pub fn candidate_modes(&self) -> Vec<RehostingMode> {
        let mut modes = Vec::new();
        if self
            .service_candidates
            .iter()
            .any(|candidate| candidate.execution_class != ServiceExecutionClass::Unsuitable)
        {
            modes.push(RehostingMode::Service);
        }
        if self
            .substrate_viability_hints
            .iter()
            .any(|hint| hint.starts_with("system:"))
        {
            modes.push(RehostingMode::System);
        }
        if self
            .substrate_viability_hints
            .iter()
            .any(|hint| hint.starts_with("reference:"))
        {
            modes.push(RehostingMode::Reference);
        }
        modes
    }

    pub fn to_execution_profile(&self) -> TargetExecutionProfile {
        TargetExecutionProfile::new(
            self.project_id.clone(),
            self.target_id.clone(),
            self.architecture.as_deref(),
            self.family_id.as_deref(),
            self.evidence.clone(),
        )
        .with_nvram_hints(
            self.nvram_facts
                .iter()
                .map(|fact| fact.key.clone())
                .collect(),
        )
        .with_network_hints(
            self.network_hypotheses
                .iter()
                .map(|network| network.interface_name.clone())
                .collect(),
        )
        .with_init_hints(
            self.init_candidates
                .iter()
                .map(|candidate| candidate.path.clone())
                .collect(),
        )
        .with_candidate_modes(self.candidate_modes())
    }
}
