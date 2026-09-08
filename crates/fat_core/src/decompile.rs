use serde::{Deserialize, Serialize};

/// Status of a function's decompilation
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DecompileStatus {
    Discovered,
    RawReady,
    RefinedReady,
    Verified,
    ReviewPending,
    Reviewed,
    SyncedToCutter,
    Stale,
}

/// Per-binary decompile workspace metadata
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecompileBinaryRecord {
    pub binary_id: String,
    pub binary_name: String,
    pub original_path: String,
    pub binary_hash: String,
    pub arch: String,
    pub endianness: String,
    pub decompiler_backend: String,
    pub created_at: String,
    pub updated_at: String,
}

/// Per-function decompile state
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecompileFunctionRecord {
    pub function_addr: String,
    pub symbol_name: Option<String>,
    pub status: DecompileStatus,
    pub latest_run_id: Option<String>,
    pub raw_lines: Option<usize>,
    pub refined_lines: Option<usize>,
    pub transform_count: Option<usize>,
    pub confirmed_count: Option<usize>,
    pub security_finding_count: Option<usize>,
    pub created_at: String,
    pub updated_at: String,
}

/// Review decisions for a function's transformations
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecompileReviewRecord {
    pub function_addr: String,
    pub auto_apply_threshold: String,
    pub decisions: Vec<ReviewDecision>,
    pub reviewed_at: Option<String>,
    pub reviewer: Option<String>,
    pub notes: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewDecision {
    pub transform_index: usize,
    pub original: String,
    pub proposed: String,
    pub user_decision: UserDecision,
    pub user_override: Option<String>,
    pub decided_at: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserDecision {
    Accepted,
    Rejected,
    Overridden,
    Pending,
}

/// Cutter sync state for a function
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecompileSyncRecord {
    pub function_addr: String,
    pub pushed: bool,
    pub functions_renamed: usize,
    pub variables_renamed: usize,
    pub comments_added: usize,
    pub pushed_at: Option<String>,
    pub cutter_url: Option<String>,
    pub errors: Vec<String>,
}

/// Record of what context was injected into a decompile run
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecompileContextRecord {
    pub sources: Vec<ContextSource>,
    pub total_tokens_estimate: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ContextSource {
    pub source_type: String, // "r2-triage", "trust-boundary", "crypto", "taint", "user-file"
    pub source_path: Option<String>,
    pub summary: String,
    pub relevance_score: f64,
    pub injected: bool,
}

// f64 does not implement Eq, so we compare via to_bits() for bitwise equality.
// This is appropriate for round-trip serde equality checks.
impl PartialEq for ContextSource {
    fn eq(&self, other: &Self) -> bool {
        self.source_type == other.source_type
            && self.source_path == other.source_path
            && self.summary == other.summary
            && self.relevance_score.to_bits() == other.relevance_score.to_bits()
            && self.injected == other.injected
    }
}

impl Eq for ContextSource {}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- serialization round-trips ----

    #[test]
    fn test_decompile_status_serde() {
        let statuses = vec![
            DecompileStatus::Discovered,
            DecompileStatus::RawReady,
            DecompileStatus::RefinedReady,
            DecompileStatus::Verified,
            DecompileStatus::ReviewPending,
            DecompileStatus::Reviewed,
            DecompileStatus::SyncedToCutter,
            DecompileStatus::Stale,
        ];
        for status in &statuses {
            let json = serde_json::to_string(status).unwrap();
            let back: DecompileStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(*status, back);
        }
        // Verify snake_case renaming
        assert_eq!(
            serde_json::to_string(&DecompileStatus::RawReady).unwrap(),
            "\"raw_ready\""
        );
        assert_eq!(
            serde_json::to_string(&DecompileStatus::SyncedToCutter).unwrap(),
            "\"synced_to_cutter\""
        );
    }

    #[test]
    fn test_decompile_binary_record_serde() {
        let record = DecompileBinaryRecord {
            binary_id: "bin-abc123".into(),
            binary_name: "httpd".into(),
            original_path: "/fw/usr/sbin/httpd".into(),
            binary_hash: "sha256:deadbeef".into(),
            arch: "mipsel".into(),
            endianness: "little".into(),
            decompiler_backend: "r2-ghidra".into(),
            created_at: "2026-04-04T00:00:00Z".into(),
            updated_at: "2026-04-04T00:00:00Z".into(),
        };
        let json = serde_json::to_string_pretty(&record).unwrap();
        let back: DecompileBinaryRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, back);
    }

    #[test]
    fn test_decompile_function_record_serde() {
        let record = DecompileFunctionRecord {
            function_addr: "0x00401000".into(),
            symbol_name: Some("main".into()),
            status: DecompileStatus::RefinedReady,
            latest_run_id: Some("run-001".into()),
            raw_lines: Some(42),
            refined_lines: Some(38),
            transform_count: Some(5),
            confirmed_count: Some(3),
            security_finding_count: Some(1),
            created_at: "2026-04-04T00:00:00Z".into(),
            updated_at: "2026-04-04T01:00:00Z".into(),
        };
        let json = serde_json::to_string_pretty(&record).unwrap();
        let back: DecompileFunctionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, back);
    }

    #[test]
    fn test_decompile_function_record_minimal_serde() {
        let record = DecompileFunctionRecord {
            function_addr: "0x00401000".into(),
            symbol_name: None,
            status: DecompileStatus::Discovered,
            latest_run_id: None,
            raw_lines: None,
            refined_lines: None,
            transform_count: None,
            confirmed_count: None,
            security_finding_count: None,
            created_at: "2026-04-04T00:00:00Z".into(),
            updated_at: "2026-04-04T00:00:00Z".into(),
        };
        let json = serde_json::to_string_pretty(&record).unwrap();
        let back: DecompileFunctionRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, back);
    }

    #[test]
    fn test_review_record_serde() {
        let record = DecompileReviewRecord {
            function_addr: "0x00401000".into(),
            auto_apply_threshold: "high".into(),
            decisions: vec![
                ReviewDecision {
                    transform_index: 0,
                    original: "var_10h".into(),
                    proposed: "buffer_size".into(),
                    user_decision: UserDecision::Accepted,
                    user_override: None,
                    decided_at: Some("2026-04-04T02:00:00Z".into()),
                },
                ReviewDecision {
                    transform_index: 1,
                    original: "fcn.00401200".into(),
                    proposed: "parse_header".into(),
                    user_decision: UserDecision::Overridden,
                    user_override: Some("parse_request_header".into()),
                    decided_at: Some("2026-04-04T02:01:00Z".into()),
                },
                ReviewDecision {
                    transform_index: 2,
                    original: "var_8h".into(),
                    proposed: "socket_fd".into(),
                    user_decision: UserDecision::Rejected,
                    user_override: None,
                    decided_at: Some("2026-04-04T02:02:00Z".into()),
                },
            ],
            reviewed_at: Some("2026-04-04T02:02:00Z".into()),
            reviewer: Some("analyst".into()),
            notes: Some("Rejected socket_fd — looks like a file descriptor, not a socket".into()),
        };
        let json = serde_json::to_string_pretty(&record).unwrap();
        let back: DecompileReviewRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, back);
    }

    #[test]
    fn test_review_decision_with_override() {
        let decision = ReviewDecision {
            transform_index: 5,
            original: "sub_rsp_8".into(),
            proposed: "alloc_stack_frame".into(),
            user_decision: UserDecision::Overridden,
            user_override: Some("setup_stack".into()),
            decided_at: Some("2026-04-04T03:00:00Z".into()),
        };
        let json = serde_json::to_string(&decision).unwrap();
        let back: ReviewDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, back);
        assert_eq!(back.user_decision, UserDecision::Overridden);
        assert_eq!(back.user_override.as_deref(), Some("setup_stack"));
    }

    #[test]
    fn test_review_decision_pending_no_override() {
        let decision = ReviewDecision {
            transform_index: 0,
            original: "var_0h".into(),
            proposed: "counter".into(),
            user_decision: UserDecision::Pending,
            user_override: None,
            decided_at: None,
        };
        let json = serde_json::to_string(&decision).unwrap();
        let back: ReviewDecision = serde_json::from_str(&json).unwrap();
        assert_eq!(decision, back);
        assert_eq!(back.user_decision, UserDecision::Pending);
        assert!(back.user_override.is_none());
        assert!(back.decided_at.is_none());
    }

    #[test]
    fn test_sync_record_serde() {
        let record = DecompileSyncRecord {
            function_addr: "0x00401000".into(),
            pushed: true,
            functions_renamed: 3,
            variables_renamed: 12,
            comments_added: 5,
            pushed_at: Some("2026-04-04T04:00:00Z".into()),
            cutter_url: Some("http://localhost:4443".into()),
            errors: vec![],
        };
        let json = serde_json::to_string_pretty(&record).unwrap();
        let back: DecompileSyncRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, back);
    }

    #[test]
    fn test_sync_record_with_errors() {
        let record = DecompileSyncRecord {
            function_addr: "0x00401000".into(),
            pushed: false,
            functions_renamed: 0,
            variables_renamed: 0,
            comments_added: 0,
            pushed_at: None,
            cutter_url: None,
            errors: vec!["connection refused".into(), "timeout after 30s".into()],
        };
        let json = serde_json::to_string_pretty(&record).unwrap();
        let back: DecompileSyncRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, back);
        assert_eq!(back.errors.len(), 2);
    }

    #[test]
    fn test_context_record_serde() {
        let record = DecompileContextRecord {
            sources: vec![
                ContextSource {
                    source_type: "r2-triage".into(),
                    source_path: Some("/project/triage/bin.json".into()),
                    summary: "Function cross-references and string refs".into(),
                    relevance_score: 0.95,
                    injected: true,
                },
                ContextSource {
                    source_type: "user-file".into(),
                    source_path: Some("/notes/analysis.md".into()),
                    summary: "Manual analysis notes".into(),
                    relevance_score: 0.5,
                    injected: false,
                },
            ],
            total_tokens_estimate: 4200,
        };
        let json = serde_json::to_string_pretty(&record).unwrap();
        let back: DecompileContextRecord = serde_json::from_str(&json).unwrap();
        assert_eq!(record, back);
    }

    // ---- DecompileStatus transition coverage ----

    #[test]
    fn test_decompile_status_all_variants_distinct() {
        let all = [
            DecompileStatus::Discovered,
            DecompileStatus::RawReady,
            DecompileStatus::RefinedReady,
            DecompileStatus::Verified,
            DecompileStatus::ReviewPending,
            DecompileStatus::Reviewed,
            DecompileStatus::SyncedToCutter,
            DecompileStatus::Stale,
        ];
        // Every variant serializes to a unique string
        let strings: Vec<String> = all
            .iter()
            .map(|s| serde_json::to_string(s).unwrap())
            .collect();
        let unique: std::collections::HashSet<&String> = strings.iter().collect();
        assert_eq!(
            strings.len(),
            unique.len(),
            "all status variants must serialize to unique strings"
        );
    }

    #[test]
    fn test_user_decision_serde() {
        let decisions = vec![
            UserDecision::Accepted,
            UserDecision::Rejected,
            UserDecision::Overridden,
            UserDecision::Pending,
        ];
        for decision in &decisions {
            let json = serde_json::to_string(decision).unwrap();
            let back: UserDecision = serde_json::from_str(&json).unwrap();
            assert_eq!(*decision, back);
        }
        assert_eq!(
            serde_json::to_string(&UserDecision::Accepted).unwrap(),
            "\"accepted\""
        );
        assert_eq!(
            serde_json::to_string(&UserDecision::Overridden).unwrap(),
            "\"overridden\""
        );
    }
}
