use fat_core::finding::FindingSeverity;
// Note: fat-toolkit-core is the package name; fat_core is the Rust identifier.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TaintFinding {
    pub id: String,
    pub title: String,
    pub severity: FindingSeverity,
    pub chain: Vec<ChainStep>,
    pub status: FindingStatus,
    pub status_reason: String,
    pub confidence: f64,
    pub source_class: SourceClass,
    /// Models selected for this run. Absent in historical or other-engine records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_provenance: Option<crate::profile::CatalogProvenance>,
    /// Shared-state family mappings used to derive a cross-binary finding.
    /// Separate from the binary source/sink models; absent in historical records.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub state_model_provenance: Option<crate::shared_state_families::SharedStateProvenance>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum FindingStatus {
    /// Chain uses ONLY DirectFlow and SymbolResolution edges.
    /// Source-level data flow confirmed end-to-end by Joern.
    Proven,

    /// Chain uses SemanticSummary edges (method summaries for libc/vendor APIs).
    /// Higher trust than Candidate but not fully machine-verified.
    Attested,

    /// Chain uses at least one overlay edge (config-key, shell-model, IPC).
    /// Data flow is inferred from synthetic patches.
    Candidate,

    /// Confirmed by dynamic test (fat emulate sent a PoC and observed side effect).
    DynamicallyConfirmed,

    /// Manually reviewed and rejected.
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceClass {
    /// Direct HTTP ingress — attacker controls the value in this request.
    Primary,

    /// Persisted/shared state — attacker may have written this value earlier.
    /// Findings require two chains to be exploitable: write-chain + read-chain.
    Secondary,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainStep {
    pub binary: String,
    pub function: String,
    pub location: String,
    pub action: String,
    pub edge_type: EdgeType,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EdgeType {
    /// Direct call or data flow within one binary. From Joern reachableByFlows.
    DirectFlow,

    /// Cross-library call resolved by import/export symbol matching.
    SymbolResolution {
        import_binary: String,
        export_library: String,
    },

    /// Config-file write/read pair matched by file path + key name.
    ConfigKeyBridge {
        config_file: String,
        config_key: String,
    },

    /// Shell script behavior modeled as pseudo-C.
    ShellModel { script: String, pattern: String },

    /// Method summary (libc semantics, vendor API summary).
    SemanticSummary { function: String, rule: String },
}

impl EdgeType {
    pub fn trust_score(&self) -> f64 {
        match self {
            EdgeType::DirectFlow => 0.95,
            EdgeType::SymbolResolution { .. } => 0.90,
            EdgeType::SemanticSummary { .. } => 0.70,
            EdgeType::ConfigKeyBridge { .. } => 0.40,
            EdgeType::ShellModel { .. } => 0.30,
        }
    }

    pub fn is_overlay(&self) -> bool {
        matches!(
            self,
            EdgeType::ConfigKeyBridge { .. } | EdgeType::ShellModel { .. }
        )
    }

    pub fn is_semantic(&self) -> bool {
        matches!(self, EdgeType::SemanticSummary { .. })
    }
}

impl TaintFinding {
    pub fn classify(chain: &[ChainStep]) -> FindingStatus {
        if chain.iter().any(|s| s.edge_type.is_overlay()) {
            FindingStatus::Candidate
        } else if chain.iter().any(|s| s.edge_type.is_semantic()) {
            FindingStatus::Attested
        } else {
            FindingStatus::Proven
        }
    }

    /// Confidence = weakest link, not product of all links.
    pub fn compute_confidence(chain: &[ChainStep]) -> f64 {
        chain
            .iter()
            .map(|step| step.edge_type.trust_score())
            .min_by(|a, b| a.partial_cmp(b).unwrap())
            .unwrap_or(0.0)
    }

    /// Strength band shared with `fat search` (STRONG / MEDIUM / WEAK), derived
    /// from the weakest-link confidence score so taint and search speak the same
    /// vocabulary.
    pub fn strength_band(&self) -> &'static str {
        strength_band_for_score(self.confidence)
    }
}

/// Map a 0.0–1.0 confidence score to the shared STRONG/MEDIUM/WEAK band.
pub fn strength_band_for_score(score: f64) -> &'static str {
    if score >= 0.8 {
        "STRONG"
    } else if score >= 0.5 {
        "MEDIUM"
    } else {
        "WEAK"
    }
}

#[cfg(test)]
mod band_tests {
    use super::strength_band_for_score;

    #[test]
    fn score_maps_to_shared_search_bands() {
        assert_eq!(strength_band_for_score(0.95), "STRONG");
        assert_eq!(strength_band_for_score(0.80), "STRONG");
        assert_eq!(strength_band_for_score(0.79), "MEDIUM");
        assert_eq!(strength_band_for_score(0.50), "MEDIUM");
        assert_eq!(strength_band_for_score(0.49), "WEAK");
        assert_eq!(strength_band_for_score(0.0), "WEAK");
    }
}
