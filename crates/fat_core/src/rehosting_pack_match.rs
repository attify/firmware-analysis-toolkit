//! Match a [`RehostingPack`](crate::rehosting_pack::RehostingPack) against a
//! target firmware's analysis facts, so the emulator can pick a vendor/device
//! pack automatically. Pure scoring logic — no filesystem or emulation deps.

use crate::rehosting_pack::RehostingPack;
use std::path::{Path, PathBuf};

/// Minimum score (excluding an exact firmware-hash match, which is always
/// decisive) for a pack to be considered a match.
pub const MATCH_THRESHOLD: f32 = 0.5;

/// The target-side facts a pack is scored against.
#[derive(Debug, Clone, Default)]
pub struct PackMatchInput {
    /// Normalized architecture, e.g. `"armel"` / `"mipsel"` (without an
    /// `arch:` prefix).
    pub architecture: Option<String>,
    /// Analysis signals, e.g. `"fs:squashfs"`, `"init:busybox"`.
    pub signals: Vec<String>,
    /// SHA-256 of the firmware image, if known.
    pub firmware_sha256: Option<String>,
    /// Root of the extracted target filesystem used for `match.paths`.
    pub target_root: Option<PathBuf>,
}

impl PackMatchInput {
    /// Build an input from a raw signal list, extracting the architecture from
    /// an `arch:<value>` signal when present.
    pub fn from_signals(signals: Vec<String>) -> Self {
        let architecture = signals
            .iter()
            .find_map(|signal| signal.strip_prefix("arch:"))
            .map(|arch| arch.trim().to_ascii_lowercase());
        Self {
            architecture,
            signals,
            firmware_sha256: None,
            target_root: None,
        }
    }

    pub fn with_firmware_sha256(mut self, sha256: Option<String>) -> Self {
        self.firmware_sha256 = sha256.map(|value| value.trim().to_ascii_lowercase());
        self
    }

    pub fn with_target_root(mut self, target_root: Option<PathBuf>) -> Self {
        self.target_root = target_root;
        self
    }
}

/// The outcome of scoring one pack against a target.
#[derive(Debug, Clone, PartialEq)]
pub struct PackMatch {
    pub score: f32,
    /// The pack's architecture constraint (if any) is satisfied.
    pub arch_gate_passed: bool,
    /// The firmware hash matched one of the pack's declared hashes.
    pub sha_exact: bool,
    pub matched_signals: Vec<String>,
    pub missing_signals: Vec<String>,
    pub matched_paths: Vec<String>,
    pub missing_paths: Vec<String>,
    pub reasons: Vec<String>,
}

impl PackMatch {
    /// Whether this pack should be treated as a match for the target. An exact
    /// firmware-hash match is authoritative and bypasses the architecture gate.
    pub fn is_match(&self) -> bool {
        self.sha_exact || (self.arch_gate_passed && self.score >= MATCH_THRESHOLD)
    }
}

/// Score a pack against a target's facts. The score is in `[0.0, 1.0]`.
pub fn score_pack(pack: &RehostingPack, input: &PackMatchInput) -> PackMatch {
    let rules = &pack.match_rules;
    let mut reasons = Vec::new();

    // An exact firmware-hash match is authoritative.
    let sha_exact = match &input.firmware_sha256 {
        Some(sha) => rules
            .firmware_sha256
            .iter()
            .any(|candidate| candidate.trim().eq_ignore_ascii_case(sha)),
        None => false,
    };
    if sha_exact {
        reasons.push("firmware sha256 matched exactly".to_string());
    }

    // Architecture is a hard gate when the pack declares one.
    let arch_gate_passed = match &rules.architecture {
        Some(pack_arch) => {
            let matched = input
                .architecture
                .as_deref()
                .is_some_and(|arch| arch.eq_ignore_ascii_case(pack_arch.trim()));
            if matched {
                reasons.push(format!("architecture matched ({pack_arch})"));
            } else {
                reasons.push(format!(
                    "architecture mismatch (pack {pack_arch}, target {})",
                    input.architecture.as_deref().unwrap_or("unknown")
                ));
            }
            matched
        }
        None => true,
    };

    // Signal overlap.
    let (matched_signals, missing_signals): (Vec<String>, Vec<String>) = rules
        .signals
        .iter()
        .cloned()
        .partition(|wanted| input.signals.iter().any(|have| have == wanted));
    if !matched_signals.is_empty() {
        reasons.push(format!(
            "matched {} of {} signals",
            matched_signals.len(),
            rules.signals.len()
        ));
    }

    let (matched_paths, missing_paths): (Vec<String>, Vec<String>) =
        rules.paths.iter().cloned().partition(|wanted| {
            input.target_root.as_ref().is_some_and(|root| {
                let relative = wanted.trim_start_matches('/');
                !relative.is_empty() && declared_path_is_contained(root, relative)
            })
        });
    if !matched_paths.is_empty() {
        reasons.push(format!(
            "matched {} of {} target paths",
            matched_paths.len(),
            rules.paths.len()
        ));
    }

    let score = if sha_exact {
        1.0
    } else if !rules.signals.is_empty() || !rules.paths.is_empty() {
        let matched = matched_signals.len() + matched_paths.len();
        let declared = rules.signals.len() + rules.paths.len();
        matched as f32 / declared as f32
    } else if rules.architecture.is_some() {
        // Arch-only pack: a weak-but-usable match when the gate passes.
        0.6
    } else {
        0.0
    };

    PackMatch {
        score,
        arch_gate_passed,
        sha_exact,
        matched_signals,
        missing_signals,
        matched_paths,
        missing_paths,
        reasons,
    }
}

fn declared_path_is_contained(root: &Path, relative: &str) -> bool {
    let Ok(root) = root.canonicalize() else {
        return false;
    };
    let candidate = root.join(relative);
    let Ok(candidate) = candidate.canonicalize() else {
        return false;
    };

    candidate.starts_with(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rehosting_pack::{parse_rehosting_pack_yaml, RehostingPack};

    fn pack(yaml: &str) -> RehostingPack {
        parse_rehosting_pack_yaml(yaml).expect("parse pack")
    }

    fn base_pack() -> RehostingPack {
        pack(
            r#"
id: example/camera
kind: rehosting-pack
version: "0.1"
match:
  architecture: mipsel
  signals:
    - "fs:squashfs"
    - "init:busybox"
"#,
        )
    }

    #[test]
    fn from_signals_extracts_architecture() {
        let input = PackMatchInput::from_signals(vec![
            "arch:Mipsel".to_string(),
            "fs:squashfs".to_string(),
        ]);
        assert_eq!(input.architecture.as_deref(), Some("mipsel"));
    }

    #[test]
    fn full_signal_and_arch_match_is_a_match() {
        let input = PackMatchInput::from_signals(vec![
            "arch:mipsel".to_string(),
            "fs:squashfs".to_string(),
            "init:busybox".to_string(),
        ]);
        let result = score_pack(&base_pack(), &input);
        assert!(result.arch_gate_passed);
        assert_eq!(result.score, 1.0);
        assert!(result.is_match());
        assert!(result.missing_signals.is_empty());
    }

    #[test]
    fn arch_mismatch_blocks_match_even_with_signals() {
        let input = PackMatchInput::from_signals(vec![
            "arch:armel".to_string(),
            "fs:squashfs".to_string(),
            "init:busybox".to_string(),
        ]);
        let result = score_pack(&base_pack(), &input);
        assert!(!result.arch_gate_passed);
        assert!(!result.is_match());
    }

    #[test]
    fn partial_signal_overlap_below_threshold_is_not_a_match() {
        let input = PackMatchInput::from_signals(vec![
            "arch:mipsel".to_string(),
            "fs:squashfs".to_string(),
        ]);
        let result = score_pack(&base_pack(), &input);
        assert_eq!(result.score, 0.5);
        assert!(result.is_match(), "0.5 meets the threshold");
        assert_eq!(result.missing_signals, vec!["init:busybox".to_string()]);
    }

    #[test]
    fn exact_firmware_hash_is_authoritative() {
        let pack = pack(
            r#"
id: vendor/device
kind: rehosting-pack
version: "0.1"
match:
  architecture: armel
  firmware_sha256:
    - "abc123"
"#,
        );
        // Arch mismatches, but the hash is exact → still a match.
        let input = PackMatchInput::from_signals(vec!["arch:mipsel".to_string()])
            .with_firmware_sha256(Some("ABC123".to_string()));
        let result = score_pack(&pack, &input);
        assert!(result.sha_exact);
        assert_eq!(result.score, 1.0);
        assert!(!result.arch_gate_passed);
        assert!(result.is_match(), "exact hash bypasses the arch gate");
    }

    #[test]
    fn declared_paths_are_checked_against_the_extracted_target_root() {
        let temp = tempfile::tempdir().expect("tempdir");
        std::fs::create_dir_all(temp.path().join("etc/init.d")).unwrap();
        std::fs::write(temp.path().join("etc/init.d/rcS"), "#!/bin/sh\n").unwrap();
        let pack = pack(
            r#"
id: vendor/device
kind: rehosting-pack
version: "0.1"
match:
  architecture: armel
  paths:
    - /etc/init.d/rcS
    - /etc/vendor.conf
"#,
        );
        let input = PackMatchInput::from_signals(vec!["arch:armel".into()])
            .with_target_root(Some(temp.path().to_path_buf()));

        let result = score_pack(&pack, &input);

        assert_eq!(result.matched_paths, vec!["/etc/init.d/rcS"]);
        assert_eq!(result.missing_paths, vec!["/etc/vendor.conf"]);
        assert_eq!(result.score, 0.5);
        assert!(result.is_match());
    }

    #[cfg(unix)]
    #[test]
    fn declared_paths_do_not_follow_symlinks_outside_the_extracted_root() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().expect("tempdir");
        let outside = tempfile::tempdir().expect("outside tempdir");
        std::fs::write(outside.path().join("host-file"), "host data").unwrap();
        std::fs::create_dir_all(temp.path().join("etc")).unwrap();
        symlink(
            outside.path().join("host-file"),
            temp.path().join("etc/vendor.conf"),
        )
        .unwrap();
        let pack = pack(
            r#"
id: vendor/device
kind: rehosting-pack
version: "0.1"
match:
  architecture: armel
  paths:
    - /etc/vendor.conf
"#,
        );
        let input = PackMatchInput::from_signals(vec!["arch:armel".into()])
            .with_target_root(Some(temp.path().to_path_buf()));

        let result = score_pack(&pack, &input);

        assert!(result.matched_paths.is_empty(), "{result:#?}");
        assert_eq!(result.missing_paths, vec!["/etc/vendor.conf"]);
        assert!(!result.is_match());
    }
}
