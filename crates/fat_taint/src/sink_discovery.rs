use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Built-in command-execution sink profile shipped inside the crate.
pub const LINUX_COMMAND_EXEC_PROFILE_YAML: &str =
    include_str!("../sink_profiles/linux-command-exec.yaml");

/// Built-in shell command-execution sink profile shipped inside the crate.
pub const SHELL_COMMAND_EXEC_PROFILE_YAML: &str =
    include_str!("../sink_profiles/shell-command-exec.yaml");

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SinkDiscoveryReport {
    pub file: String,
    pub binary: BinaryContext,
    #[serde(default)]
    pub profiles: Vec<String>,
    pub summary: SinkDiscoverySummary,
    #[serde(default)]
    pub candidates: Vec<SinkCandidate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BinaryContext {
    pub format: String,
    pub arch: String,
    pub bits: u8,
    pub endianness: String,
    pub class: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stripped: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SinkDiscoverySummary {
    #[serde(default)]
    pub candidates: usize,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub families: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SinkCandidate {
    pub id: String,
    pub family: SinkFamily,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub family_key: String,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "hex_u64_option"
    )]
    pub address: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub symbolic_name: Option<String>,
    pub confidence: Confidence,
    pub score: f64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub providers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<SinkEvidence>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SinkFamily {
    CommandExec,
    ConfigRead,
    ConfigWrite,
    InputSource,
    StringOverflow,
    NetworkEgress,
    FileWrite,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Confidence {
    Weak,
    Probable,
    Strong,
    Confirmed,
}

/// Finding severity band declared per shell-profile family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Severity {
    High,
    Medium,
    Low,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SinkEvidence {
    StringRef {
        profile: String,
        rule: String,
        value: String,
        #[serde(with = "hex_u64")]
        vaddr: u64,
        score_delta: f64,
    },
    PointerXref {
        profile: String,
        rule: String,
        #[serde(with = "hex_u64")]
        pointer_vaddr: u64,
        #[serde(with = "hex_u64")]
        points_to: u64,
        score_delta: f64,
    },
    CodeRef {
        profile: String,
        rule: String,
        #[serde(with = "hex_u64")]
        function: u64,
        score_delta: f64,
    },
    CodePattern {
        profile: String,
        rule: String,
        #[serde(with = "hex_u64")]
        function: u64,
        score_delta: f64,
    },
    Symbol {
        profile: String,
        rule: String,
        value: String,
        #[serde(with = "hex_u64")]
        address: u64,
        score_delta: f64,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SinkProfile {
    pub name: String,
    pub version: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub applies_to: Option<AppliesTo>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detect: Option<ProfileDetect>,
    /// Target class the profile consumes: `binary` (ELF evidence, the default)
    /// or `shell` (line-scan over rootfs scripts).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    #[serde(default)]
    pub families: BTreeMap<String, FamilyProfile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct AppliesTo {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub arch: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub formats: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(deny_unknown_fields)]
pub struct ProfileDetect {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub imports: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub strings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FamilyProfile {
    #[serde(default)]
    pub dangerous_arg: u8,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub string_seeds: Vec<StringSeed>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pointer_xrefs: Option<PointerXrefs>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub code_patterns: Vec<CodePatternRule>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub wrapper_names: Vec<WrapperName>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confidence: Option<ConfidenceThresholds>,
    /// Source-level regex applied per line by the shell-target scanner
    /// (`target: shell` profiles only).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    /// Default severity reported for findings in this family.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub severity: Option<Severity>,
    /// Human-readable explanation of what the family matches.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StringSeed {
    pub value: String,
    pub weight: f64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub tags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WrapperName {
    pub name: String,
    pub dangerous_arg: u8,
    pub weight: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PointerXrefs {
    pub enabled: bool,
    pub weight: f64,
    pub scan: String,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CodePatternRule {
    pub id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,
    pub weight: f64,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfidenceThresholds {
    pub weak: f64,
    pub probable: f64,
    pub strong: f64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub confirmed: Option<f64>,
}

pub fn parse_sink_profile(yaml: &str) -> Result<SinkProfile, String> {
    let profile: SinkProfile = serde_yaml::from_str(yaml).map_err(|e| e.to_string())?;
    profile.validate()?;
    Ok(profile)
}

pub fn score_candidate(
    family_key: &str,
    address: Option<u64>,
    providers: Vec<String>,
    evidence: Vec<SinkEvidence>,
    thresholds: Option<ConfidenceThresholds>,
) -> Option<SinkCandidate> {
    let score = score_evidence(&evidence);
    let confidence = confidence_for_score(score, thresholds.as_ref())?;

    Some(SinkCandidate {
        id: String::new(),
        family: parse_sink_family(family_key),
        family_key: family_key.to_string(),
        address,
        symbolic_name: None,
        confidence,
        score,
        providers,
        evidence,
        limitations: vec!["function context not proven".to_string()],
    })
}

impl SinkProfile {
    pub fn validate(&self) -> Result<(), String> {
        validate_sink_profile(self)
    }
}

fn validate_sink_profile(profile: &SinkProfile) -> Result<(), String> {
    if profile.name.trim().is_empty() {
        return Err("profile name must be non-empty".to_string());
    }
    if profile.families.is_empty() {
        return Err("profile must define at least one sink family".to_string());
    }

    for (family_name, family) in &profile.families {
        for seed in &family.string_seeds {
            if seed.value.trim().is_empty() {
                return Err(format!(
                    "family '{family_name}' has an empty string seed value"
                ));
            }
            validate_weight(seed.weight, "string seed weight")?;
        }

        if let Some(pointer_xrefs) = &family.pointer_xrefs {
            validate_weight(pointer_xrefs.weight, "pointer xrefs weight")?;
        }

        for wrapper in &family.wrapper_names {
            validate_weight(wrapper.weight, "wrapper name weight")?;
        }

        if let Some(pattern) = &family.pattern {
            if pattern.trim().is_empty() {
                return Err(format!("family '{family_name}' has an empty pattern"));
            }
            if let Err(err) = regex::Regex::new(pattern) {
                return Err(format!(
                    "family '{family_name}' has an invalid pattern '{pattern}': {err}"
                ));
            }
        }

        for pattern in &family.code_patterns {
            validate_weight(pattern.weight, "code pattern weight")?;
            if pattern.id.trim().is_empty() {
                return Err(format!(
                    "family '{family_name}' has a code pattern with an empty id"
                ));
            }
            if let Some(arch) = &pattern.arch {
                if arch.trim().is_empty() {
                    return Err(format!(
                        "family '{}' has a code pattern '{}' with an empty arch",
                        family_name, pattern.id
                    ));
                }
            }
        }

        if let Some(confidence) = &family.confidence {
            validate_weight(confidence.weak, "confidence weak threshold")?;
            validate_weight(confidence.probable, "confidence probable threshold")?;
            validate_weight(confidence.strong, "confidence strong threshold")?;
            if confidence.weak > confidence.probable {
                return Err(format!(
                    "family '{family_name}' has unordered confidence thresholds: weak > probable"
                ));
            }
            if confidence.probable > confidence.strong {
                return Err(format!(
                    "family '{family_name}' has unordered confidence thresholds: probable > strong"
                ));
            }
            if let Some(confirmed) = confidence.confirmed {
                validate_weight(confirmed, "confidence confirmed threshold")?;
                if confidence.strong > confirmed {
                    return Err(format!(
                        "family '{family_name}' has unordered confidence thresholds: strong > confirmed"
                    ));
                }
            }
        }
    }

    Ok(())
}

fn validate_weight(value: f64, label: &str) -> Result<(), String> {
    if !value.is_finite() {
        return Err(format!("{label} must be finite"));
    }
    if !(0.0..=1.0).contains(&value) {
        return Err(format!("{label} must be within 0.0..=1.0"));
    }
    Ok(())
}

pub fn confidence_for_score(
    score: f64,
    thresholds: Option<&ConfidenceThresholds>,
) -> Option<Confidence> {
    let thresholds = thresholds.cloned().unwrap_or(ConfidenceThresholds {
        weak: 0.25,
        probable: 0.55,
        strong: 0.80,
        confirmed: None,
    });

    if let Some(confirmed) = thresholds.confirmed {
        if score >= confirmed {
            return Some(Confidence::Confirmed);
        }
    }
    if score >= thresholds.strong {
        Some(Confidence::Strong)
    } else if score >= thresholds.probable {
        Some(Confidence::Probable)
    } else if score >= thresholds.weak {
        Some(Confidence::Weak)
    } else {
        None
    }
}

fn score_delta(evidence: &SinkEvidence) -> f64 {
    match evidence {
        SinkEvidence::StringRef { score_delta, .. }
        | SinkEvidence::PointerXref { score_delta, .. }
        | SinkEvidence::CodeRef { score_delta, .. }
        | SinkEvidence::CodePattern { score_delta, .. }
        | SinkEvidence::Symbol { score_delta, .. } => *score_delta,
    }
}

fn score_evidence(evidence: &[SinkEvidence]) -> f64 {
    let mut by_signal = BTreeMap::<String, f64>::new();
    for item in evidence {
        let key = score_signal_key(item);
        let delta = score_delta(item);
        by_signal
            .entry(key)
            .and_modify(|current| *current = current.max(delta))
            .or_insert(delta);
    }
    by_signal.values().sum()
}

fn score_signal_key(evidence: &SinkEvidence) -> String {
    match evidence {
        SinkEvidence::StringRef { profile, rule, .. } => format!("string_ref:{profile}:{rule}"),
        SinkEvidence::PointerXref { profile, rule, .. } => {
            format!("pointer_xref:{profile}:{rule}")
        }
        SinkEvidence::CodeRef { profile, rule, .. } => format!("code_ref:{profile}:{rule}"),
        SinkEvidence::CodePattern { profile, rule, .. } => {
            format!("code_pattern:{profile}:{rule}")
        }
        SinkEvidence::Symbol {
            profile,
            rule,
            value,
            ..
        } => format!("symbol:{profile}:{rule}:{value}"),
    }
}

fn parse_sink_family(name: &str) -> SinkFamily {
    match name {
        "command-exec" => SinkFamily::CommandExec,
        "config-read" => SinkFamily::ConfigRead,
        "config-write" => SinkFamily::ConfigWrite,
        "input-source" => SinkFamily::InputSource,
        "string-overflow" => SinkFamily::StringOverflow,
        "network-egress" => SinkFamily::NetworkEgress,
        "file-write" => SinkFamily::FileWrite,
        _ => SinkFamily::Unknown,
    }
}

mod hex_u64 {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(value: &u64, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&format!("0x{value:08x}"))
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<u64, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = u64;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("a hex string like 0x00413f10 or an integer")
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
                Ok(value)
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                u64::try_from(value).map_err(E::custom)
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                let raw = value.trim();
                if let Some(raw) = raw.strip_prefix("0x").or_else(|| raw.strip_prefix("0X")) {
                    u64::from_str_radix(raw, 16).map_err(E::custom)
                } else {
                    raw.parse::<u64>().map_err(E::custom)
                }
            }
        }

        deserializer.deserialize_any(Visitor)
    }
}

mod hex_u64_option {
    use super::hex_u64;
    use serde::{Deserializer, Serializer};

    pub fn serialize<S>(value: &Option<u64>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match value {
            Some(value) => hex_u64::serialize(value, serializer),
            None => serializer.serialize_none(),
        }
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Option<u64>, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = Option<u64>;

            fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str("an optional hex address")
            }

            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(None)
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(None)
            }

            fn visit_some<D2>(self, deserializer: D2) -> Result<Self::Value, D2::Error>
            where
                D2: Deserializer<'de>,
            {
                hex_u64::deserialize(deserializer).map(Some)
            }
        }

        deserializer.deserialize_option(Visitor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_serializes_stable_candidate_contract() {
        let report = SinkDiscoveryReport {
            file: "./bin/httpd".into(),
            binary: BinaryContext {
                format: "ELF".into(),
                arch: "mips".into(),
                bits: 32,
                endianness: "little".into(),
                class: "ELF32".into(),
                stripped: Some(true),
            },
            profiles: vec!["linux-command-exec".into()],
            summary: SinkDiscoverySummary::default(),
            candidates: vec![SinkCandidate {
                id: "sink-0".into(),
                family: SinkFamily::CommandExec,
                family_key: "command-exec".into(),
                address: Some(0x00413f10),
                symbolic_name: Some("candidate_system".into()),
                confidence: Confidence::Probable,
                score: 0.82,
                providers: vec!["mips-string-ref".into()],
                evidence: vec![SinkEvidence::StringRef {
                    profile: "linux-command-exec".into(),
                    rule: "string_seeds:/bin/sh".into(),
                    value: "/bin/sh".into(),
                    vaddr: 0x004f2ed0,
                    score_delta: 0.35,
                }],
                limitations: vec!["reachability from request handler not proven".into()],
            }],
        };

        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["candidates"][0]["family"], "command-exec");
        assert_eq!(json["candidates"][0]["family_key"], "command-exec");
        assert_eq!(json["candidates"][0]["confidence"], "probable");
        assert_eq!(json["candidates"][0]["evidence"][0]["kind"], "string_ref");
        assert_eq!(json["candidates"][0]["address"], "0x00413f10");
        assert_eq!(json["candidates"][0]["evidence"][0]["vaddr"], "0x004f2ed0");
        assert_eq!(json["profiles"], serde_json::json!(["linux-command-exec"]));
        assert!(json["candidates"].is_array());
    }

    #[test]
    fn addresses_serialize_as_hex_strings() {
        let evidence = SinkEvidence::PointerXref {
            profile: "linux-command-exec".into(),
            rule: "pointer_xrefs".into(),
            pointer_vaddr: 0x004f8a10,
            points_to: 0x004f2ed0,
            score_delta: 0.20,
        };
        let json = serde_json::to_value(&evidence).unwrap();
        assert_eq!(json["kind"], "pointer_xref");
        assert_eq!(json["pointer_vaddr"], "0x004f8a10");
        assert_eq!(json["points_to"], "0x004f2ed0");
    }

    #[test]
    fn confidence_orders_by_strength() {
        assert!(Confidence::Weak < Confidence::Probable);
        assert!(Confidence::Probable < Confidence::Strong);
        assert!(Confidence::Strong < Confidence::Confirmed);
    }

    #[test]
    fn empty_report_keeps_array_shape() {
        let report = SinkDiscoveryReport {
            file: "./bin/httpd".into(),
            binary: BinaryContext {
                format: "ELF".into(),
                arch: "mips".into(),
                bits: 32,
                endianness: "little".into(),
                class: "ELF32".into(),
                stripped: None,
            },
            profiles: vec![],
            summary: SinkDiscoverySummary::default(),
            candidates: vec![],
        };

        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["profiles"], serde_json::json!([]));
        assert_eq!(json["candidates"], serde_json::json!([]));
    }

    #[test]
    fn parses_linux_command_exec_profile() {
        let profile = parse_sink_profile(LINUX_COMMAND_EXEC_PROFILE_YAML).unwrap();
        assert_eq!(profile.name, "linux-command-exec");
        assert!(profile.families.contains_key("command-exec"));
    }

    #[test]
    fn parses_shell_command_exec_profile() {
        let profile = parse_sink_profile(SHELL_COMMAND_EXEC_PROFILE_YAML).unwrap();
        assert_eq!(profile.name, "shell-command-exec");
        assert_eq!(profile.target.as_deref(), Some("shell"));
        let expected = [
            ("dynamic-eval", Severity::High),
            ("sed-var-injection", Severity::High),
            ("insmod-var-path", Severity::Medium),
            ("backtick-var-subst", Severity::Medium),
            ("dollar-paren-var-subst", Severity::Medium),
            ("unquoted-var-as-path", Severity::Medium),
            ("sh-c-var", Severity::High),
            ("tmpfs-staged-exec", Severity::High),
        ];
        for (family, severity) in expected {
            let family_profile = profile
                .families
                .get(family)
                .unwrap_or_else(|| panic!("missing family {family}"));
            assert!(
                family_profile.pattern.is_some(),
                "{family} must declare a pattern"
            );
            assert_eq!(family_profile.severity, Some(severity));
        }
    }

    /// Regression: `mkfs\.[a-z]+` stopped before the trailing
    /// digit of `mkfs.ext4`, leaving the alternation's `\b` wedged between two
    /// word characters where it can never hold, so every digit-suffixed mkfs
    /// variant silently failed to match.
    #[test]
    fn unquoted_var_as_path_matches_digit_suffixed_mkfs_variants() {
        let profile = parse_sink_profile(SHELL_COMMAND_EXEC_PROFILE_YAML).unwrap();
        let pattern = profile
            .families
            .get("unquoted-var-as-path")
            .and_then(|family| family.pattern.as_deref())
            .expect("unquoted-var-as-path pattern");
        let regex = regex::Regex::new(pattern).unwrap();

        for line in [
            "mkfs.ext2 $dev",
            "mkfs.ext3 $dev",
            "mkfs.ext4 $dev",
            "mkfs.f2fs $dev",
            "mkfs.fat32 $dev",
            "mkfs.jffs2 $dev",
            "mkfs.ubifs $dev",
            // Suffixes that already matched before the fix must keep matching.
            "mkfs.vfat $dev",
            "mkfs.minix $dev",
            "/sbin/mkfs.ext4 $dev",
            "mount $part /mnt/usb",
            "cp $src /tmp/out",
            "mv $src /tmp/out",
            "rm $target",
        ] {
            assert!(regex.is_match(line), "expected a match for {line:?}");
        }

        for line in [
            // Quoted argument: the `[^"]*` bridge cannot cross the quote.
            "mount \"$part\" /mnt/usb",
            // Longer commands that merely start with an alternative.
            "cpio -i < $archive",
            "rmdir $stale",
            "mvn package $args",
            "mountpoint -q $dir",
            // No variable in the argument list at all.
            "mkfs.ext4 /dev/sda1",
        ] {
            assert!(!regex.is_match(line), "unexpected match for {line:?}");
        }
    }

    /// The shells `sh-c-var` and `tmpfs-staged-exec` name explicitly. `ash` is
    /// busybox's shell and so the most common of these in an embedded rootfs;
    /// `mksh` is Android's `/system/bin/sh`.
    const SHELL_NAMES: &[&str] = &["sh", "ash", "bash", "dash", "hush", "mksh", "ksh"];

    /// Words that merely *end* in a shell name. `\b(sh|ash|...)` must not match
    /// inside any of them — matching a suffix is
    /// the failure mode an alternation could reintroduce if a name were added
    /// that is a common word suffix.
    const NOT_SHELLS: &[&str] = &[
        "flush",
        "refresh",
        "publish",
        "flash",
        "splash",
        "wash",
        "cache_refresh",
    ];

    /// Regression: `sed-var-injection`, `insmod-var-path`,
    /// `sh-c-var` and `tmpfs-staged-exec` anchored on a bare command name with
    /// no leading `\b`, so each also matched as the suffix of a longer word
    /// (`parsed`, `xinsmod`, `flush`, `flash`). The added boundary must not
    /// cost the absolute-path forms, since `/` is a non-word character and the
    /// boundary still holds between it and the command name.
    #[test]
    fn command_anchored_families_require_a_leading_word_boundary() {
        let profile = parse_sink_profile(SHELL_COMMAND_EXEC_PROFILE_YAML).unwrap();
        let compiled = |family: &str| {
            let pattern = profile
                .families
                .get(family)
                .and_then(|def| def.pattern.as_deref())
                .unwrap_or_else(|| panic!("{family} pattern"));
            regex::Regex::new(pattern).unwrap()
        };

        // (family, must-match lines, must-not-match lines)
        let cases: &[(&str, &[&str], &[&str])] = &[
            (
                "sed-var-injection",
                &[
                    "sed -i \"s/old/$ver/g\" /etc/config",
                    "/bin/sed -i \"s/old/$ver/g\" /etc/config",
                    "/usr/bin/sed -e \"s/old/$ver/\" /etc/config",
                    // busybox applet form: the space is a non-word character.
                    "busybox sed -i \"s/old/$ver/g\" /etc/config",
                ],
                &[
                    // The false positive from the issue: `parsed` ends in `sed`.
                    "parsed -i \"s/a/$x/g\" f",
                    "unparsed -i \"s/a/$x/g\" f",
                    "passed -i \"$x\" f",
                    "based -i \"$x\" f",
                ],
            ),
            (
                "insmod-var-path",
                &[
                    "insmod $mod",
                    "/sbin/insmod $mod",
                    "busybox insmod $mod",
                    "insmod /lib/modules/$ver/wl.ko",
                ],
                &["xinsmod $mod", "myinsmod $mod"],
            ),
        ];

        for (family, matches, rejects) in cases {
            let regex = compiled(family);
            for line in *matches {
                assert!(
                    regex.is_match(line),
                    "{family}: expected a match for {line:?}"
                );
            }
            for line in *rejects {
                assert!(
                    !regex.is_match(line),
                    "{family}: unexpected match for {line:?}"
                );
            }
        }
    }

    /// Shell-alternation regression: adding the leading `\b` to a
    /// bare `sh` anchor silently dropped `ash -c "$x"` / `bash /tmp/x`, which
    /// the pattern had matched incidentally as a suffix. `ash` is busybox's
    /// shell, so that false negative was worse than the false positive the
    /// boundary fixes. Both families now name the shells explicitly; every
    /// alternative must match plain and by absolute path, and no word that
    /// merely ends in a shell name may match.
    #[test]
    fn shell_families_cover_every_named_shell_and_no_longer_word() {
        let profile = parse_sink_profile(SHELL_COMMAND_EXEC_PROFILE_YAML).unwrap();
        let compiled = |family: &str| {
            let pattern = profile
                .families
                .get(family)
                .and_then(|def| def.pattern.as_deref())
                .unwrap_or_else(|| panic!("{family} pattern"));
            regex::Regex::new(pattern).unwrap()
        };

        // (family, how a line invoking `shell` looks)
        let families: &[(&str, fn(&str) -> String)] = &[
            ("sh-c-var", |cmd| format!("{cmd} -c \"$cmd\"")),
            ("tmpfs-staged-exec", |cmd| format!("{cmd} /tmp/run.sh")),
        ];

        for (family, render) in families {
            let regex = compiled(family);
            for shell in SHELL_NAMES {
                for invocation in [
                    shell.to_string(),
                    format!("/bin/{shell}"),
                    // Android stages its shell under /system/bin.
                    format!("/system/bin/{shell}"),
                    // busybox applet dispatch.
                    format!("busybox {shell}"),
                ] {
                    let line = render(&invocation);
                    assert!(
                        regex.is_match(&line),
                        "{family}: expected a match for {line:?}"
                    );
                }
            }

            for word in NOT_SHELLS {
                for invocation in [word.to_string(), format!("/usr/sbin/{word}")] {
                    let line = render(&invocation);
                    assert!(
                        !regex.is_match(&line),
                        "{family}: unexpected match for {line:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn rejects_invalid_family_pattern() {
        let yaml = r#"
name: bad
version: 1
families:
  dynamic-eval:
    pattern: "(unclosed"
    severity: high
"#;
        assert!(parse_sink_profile(yaml).is_err());
    }

    #[test]
    fn rejects_negative_profile_weights() {
        let yaml = r#"
name: bad
version: 1
families:
  command-exec:
    string_seeds:
      - value: "/bin/sh"
        weight: -0.1
"#;
        assert!(parse_sink_profile(yaml).is_err());
    }

    #[test]
    fn rejects_profiles_without_families() {
        let yaml = r#"
name: bad
version: 1
"#;
        assert!(parse_sink_profile(yaml).is_err());
    }

    #[test]
    fn rejects_empty_seed_value() {
        let yaml = r#"
name: bad
version: 1
families:
  command-exec:
    string_seeds:
      - value: ""
        weight: 0.1
"#;
        assert!(parse_sink_profile(yaml).is_err());
    }

    #[test]
    fn rejects_unordered_confidence_thresholds() {
        let yaml = r#"
name: bad
version: 1
families:
  command-exec:
    confidence:
      weak: 0.6
      probable: 0.5
      strong: 0.8
"#;
        assert!(parse_sink_profile(yaml).is_err());
    }

    #[test]
    fn rejects_unknown_profile_fields() {
        let yaml = r#"
name: bad
version: 1
unexpected: true
"#;
        assert!(parse_sink_profile(yaml).is_err());
    }

    #[test]
    fn hex_and_decimal_address_strings_deserialize() {
        #[derive(Deserialize)]
        struct Wrapper {
            #[serde(with = "super::hex_u64")]
            value: u64,
        }

        let decimal: Wrapper = serde_json::from_str(r#"{"value":"10"}"#).unwrap();
        let hex: Wrapper = serde_json::from_str(r#"{"value":"0x10"}"#).unwrap();
        assert_eq!(decimal.value, 10);
        assert_eq!(hex.value, 16);
    }

    #[test]
    fn scorer_upgrades_pointer_and_code_pattern_to_strong() {
        let candidate = score_candidate(
            "command-exec",
            Some(0x00413f10),
            vec![
                "mips-string-ref".into(),
                "pointer-xref".into(),
                "mips-code-pattern".into(),
            ],
            vec![
                SinkEvidence::StringRef {
                    profile: "linux-command-exec".into(),
                    rule: "string_seeds:/bin/sh".into(),
                    value: "/bin/sh".into(),
                    vaddr: 0x004f2ed0,
                    score_delta: 0.35,
                },
                SinkEvidence::PointerXref {
                    profile: "linux-command-exec".into(),
                    rule: "pointer_xrefs".into(),
                    pointer_vaddr: 0x004f8a10,
                    points_to: 0x004f2ed0,
                    score_delta: 0.20,
                },
                SinkEvidence::CodePattern {
                    profile: "linux-command-exec".into(),
                    rule: "mips-execve-like-argv-setup".into(),
                    function: 0x00413f10,
                    score_delta: 0.35,
                },
            ],
            Some(ConfidenceThresholds {
                weak: 0.25,
                probable: 0.55,
                strong: 0.80,
                confirmed: None,
            }),
        )
        .expect("candidate should meet weak threshold");

        assert_eq!(candidate.family_key, "command-exec");
        assert_eq!(candidate.confidence, Confidence::Strong);
        assert_eq!(
            candidate.providers,
            vec!["mips-string-ref", "pointer-xref", "mips-code-pattern"]
        );
    }

    #[test]
    fn scorer_suppresses_evidence_below_weak_threshold() {
        let candidate = score_candidate(
            "command-exec",
            None,
            vec!["mips-string-ref".into()],
            vec![SinkEvidence::StringRef {
                profile: "linux-command-exec".into(),
                rule: "string_seeds:/bin/sh".into(),
                value: "/bin/sh".into(),
                vaddr: 0x004f2ed0,
                score_delta: 0.20,
            }],
            Some(ConfidenceThresholds {
                weak: 0.25,
                probable: 0.55,
                strong: 0.80,
                confirmed: None,
            }),
        );

        assert!(candidate.is_none());
    }

    #[test]
    fn scorer_does_not_upgrade_repeated_string_seed_hits() {
        let candidate = score_candidate(
            "command-exec",
            None,
            vec!["mips-string-ref".into()],
            vec![
                SinkEvidence::StringRef {
                    profile: "linux-command-exec".into(),
                    rule: "string_seeds:/bin/sh".into(),
                    value: "/bin/sh".into(),
                    vaddr: 0x004f2ed0,
                    score_delta: 0.35,
                },
                SinkEvidence::StringRef {
                    profile: "linux-command-exec".into(),
                    rule: "string_seeds:/bin/sh".into(),
                    value: "/bin/sh".into(),
                    vaddr: 0x004f3000,
                    score_delta: 0.35,
                },
                SinkEvidence::StringRef {
                    profile: "linux-command-exec".into(),
                    rule: "string_seeds:/bin/sh".into(),
                    value: "/bin/sh".into(),
                    vaddr: 0x004f4000,
                    score_delta: 0.35,
                },
            ],
            Some(ConfidenceThresholds {
                weak: 0.25,
                probable: 0.55,
                strong: 0.80,
                confirmed: None,
            }),
        )
        .expect("repeated string seed evidence still meets weak threshold");

        assert_eq!(candidate.confidence, Confidence::Weak);
        assert_eq!(candidate.score, 0.35);
        assert_eq!(candidate.evidence.len(), 3);
    }
}
