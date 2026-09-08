use serde::{Deserialize, Serialize};

/// Unknown keys are rejected rather than defaulted.
///
/// `modified_fixture` and `fixture_mutations` carry the pack's fidelity
/// declaration, and both are `#[serde(default)]`. Without this, a pack naming
/// them wrongly — a legacy spelling or a plain typo — would deserialize to "not
/// modified, no mutations" and be accepted as a faithful profile, which is the
/// one claim the guardrail exists to prevent a pack from making silently.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RehostingPack {
    pub id: String,
    pub kind: String,
    pub version: String,
    /// The pack describes a fixture that has been altered from the firmware as
    /// shipped. It is not a faithful rehosting profile, and results obtained
    /// with it must not be read as behaviour of the original image.
    #[serde(default)]
    pub modified_fixture: bool,
    #[serde(default, rename = "match")]
    pub match_rules: RehostingPackMatch,
    #[serde(default)]
    pub partitions: Option<PackPartitions>,
    #[serde(default)]
    pub runtime: Option<PackRuntime>,
    #[serde(default)]
    pub repairs: Option<PackRepairs>,
    #[serde(default)]
    pub validators: Vec<PackValidator>,
    #[serde(default)]
    pub caveats: Vec<String>,
    #[serde(default)]
    pub fixture_mutations: Vec<PackFixtureMutation>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RehostingPackMatch {
    #[serde(default)]
    pub architecture: Option<String>,
    #[serde(default)]
    pub firmware_sha256: Vec<String>,
    #[serde(default)]
    pub signals: Vec<String>,
    #[serde(default)]
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackPartitions {
    #[serde(default)]
    pub roles: Vec<PackPartitionRole>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackPartitionRole {
    pub source: String,
    pub mount: String,
    #[serde(default)]
    pub materialization: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackRuntime {
    #[serde(default)]
    pub substrate: Option<String>,
    #[serde(default)]
    pub qemu_machine: Option<String>,
    #[serde(default)]
    pub network: Option<PackNetwork>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackNetwork {
    #[serde(default)]
    pub interface: Option<String>,
    #[serde(default)]
    pub mode: Option<String>,
    #[serde(default)]
    pub fallback_ip: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackRepairs {
    #[serde(default)]
    pub init: Option<PackInitRepairs>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackInitRepairs {
    #[serde(default)]
    pub skip_module_loads_matching: Vec<String>,
    #[serde(default)]
    pub skip_commands: Vec<String>,
    #[serde(default)]
    pub materialize_paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackValidator {
    pub goal: String,
    pub kind: String,
    #[serde(default)]
    pub pattern: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    #[serde(default)]
    pub path: Option<String>,
    #[serde(default)]
    pub port: Option<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackFixtureMutation {
    pub kind: String,
    #[serde(default)]
    pub path: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RehostingPackValidationReport {
    pub pack_id: Option<String>,
    pub valid: bool,
    pub errors: Vec<RehostingPackValidationMessage>,
    pub warnings: Vec<RehostingPackValidationMessage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RehostingPackValidationMessage {
    pub code: String,
    pub message: String,
}

pub fn parse_rehosting_pack_yaml(input: &str) -> Result<RehostingPack, String> {
    serde_yaml::from_str(input).map_err(|err| err.to_string())
}

pub fn validate_rehosting_pack(pack: &RehostingPack) -> RehostingPackValidationReport {
    let mut report = RehostingPackValidationReport {
        pack_id: nonempty(pack.id.as_str()).map(str::to_string),
        valid: true,
        errors: Vec::new(),
        warnings: Vec::new(),
    };

    validate_identity(pack, &mut report);
    validate_matcher(pack, &mut report);
    validate_partitions(pack, &mut report);
    validate_runtime(pack, &mut report);
    validate_repairs(pack, &mut report);
    validate_validators(pack, &mut report);
    validate_fixture_mutations(pack, &mut report);

    if pack.caveats.is_empty() {
        report.warn(
            "missing-caveats",
            "pack has no caveats; rehosting packs should state fidelity boundaries explicitly",
        );
    }

    report.valid = report.errors.is_empty();
    report
}

fn validate_runtime(pack: &RehostingPack, report: &mut RehostingPackValidationReport) {
    let Some(runtime) = pack.runtime.as_ref() else {
        return;
    };

    if let Some(substrate) = runtime.substrate.as_deref() {
        if !matches!(substrate.trim(), "service" | "system" | "reference") {
            report.error(
                "invalid-runtime-substrate",
                format!(
                    "runtime substrate must be service, system, or reference; got '{substrate}'"
                ),
            );
        }
    }
}

impl RehostingPackValidationReport {
    pub fn error(&mut self, code: &str, message: impl Into<String>) {
        self.errors.push(RehostingPackValidationMessage {
            code: code.to_string(),
            message: message.into(),
        });
    }

    pub fn warn(&mut self, code: &str, message: impl Into<String>) {
        self.warnings.push(RehostingPackValidationMessage {
            code: code.to_string(),
            message: message.into(),
        });
    }
}

fn validate_identity(pack: &RehostingPack, report: &mut RehostingPackValidationReport) {
    if nonempty(pack.id.as_str()).is_none() {
        report.error("missing-id", "pack id is required");
    }
    if pack.kind != "rehosting-pack" {
        report.error(
            "invalid-kind",
            format!("pack kind must be 'rehosting-pack', got '{}'", pack.kind),
        );
    }
    if nonempty(pack.version.as_str()).is_none() {
        report.error("missing-version", "pack version is required");
    }
}

fn validate_matcher(pack: &RehostingPack, report: &mut RehostingPackValidationReport) {
    let anchors = pack.match_rules.firmware_sha256.len()
        + pack.match_rules.signals.len()
        + pack.match_rules.paths.len();

    if pack.match_rules.architecture.is_none() && anchors == 0 {
        report.error(
            "missing-matcher",
            "pack must include architecture, firmware hash, signal, or path match evidence",
        );
        return;
    }

    if pack.match_rules.firmware_sha256.is_empty() && anchors < 2 {
        report.error(
            "matcher-overbroad",
            "pack matcher is too broad; add at least two device/family anchors beyond architecture or a firmware hash",
        );
    }

    for path in &pack.match_rules.paths {
        validate_guest_path(report, "invalid-match-path", path);
    }
}

fn validate_partitions(pack: &RehostingPack, report: &mut RehostingPackValidationReport) {
    let Some(partitions) = pack.partitions.as_ref() else {
        return;
    };

    for role in &partitions.roles {
        if nonempty(role.source.as_str()).is_none() {
            report.error(
                "invalid-partition-source",
                "partition role source is required",
            );
        }
        validate_guest_path(report, "invalid-partition-mount", role.mount.as_str());
        if let Some(materialization) = role.materialization.as_deref() {
            if matches!(
                materialization,
                "in-place" | "destructive" | "mutate-source"
            ) {
                report.error(
                    "destructive-materialization",
                    format!(
                        "partition '{}' uses destructive materialization '{}'",
                        role.source, materialization
                    ),
                );
            }
        }
    }
}

fn validate_repairs(pack: &RehostingPack, report: &mut RehostingPackValidationReport) {
    let Some(init) = pack
        .repairs
        .as_ref()
        .and_then(|repairs| repairs.init.as_ref())
    else {
        return;
    };

    for path in &init.materialize_paths {
        validate_guest_path(report, "invalid-materialized-path", path);
    }
    for command in &init.skip_commands {
        if command.is_empty()
            || matches!(command.as_str(), "mount" | "insmod")
            || !command.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.' | b'+')
            })
        {
            report.error(
                "invalid-skip-command",
                format!("skip command must be a safe command basename; got '{command}'"),
            );
        }
    }
    for pattern in &init.skip_module_loads_matching {
        if pattern.is_empty()
            || !pattern.bytes().all(|byte| {
                byte.is_ascii_alphanumeric()
                    || matches!(byte, b'_' | b'-' | b'.' | b'+' | b'*' | b'?')
            })
        {
            report.error(
                "invalid-module-skip-pattern",
                format!("module skip pattern contains unsafe characters; got '{pattern}'"),
            );
        }
    }

    if (!init.skip_commands.is_empty() || !init.skip_module_loads_matching.is_empty())
        && pack.caveats.is_empty()
    {
        report.warn(
            "repair-without-caveat",
            "init repair skips commands or modules but no fidelity caveat explains the boundary",
        );
    }
}

fn validate_validators(pack: &RehostingPack, report: &mut RehostingPackValidationReport) {
    if pack.validators.is_empty() {
        report.error(
            "missing-validators",
            "pack must define at least one validator so success claims are testable",
        );
        return;
    }

    for validator in &pack.validators {
        if nonempty(validator.goal.as_str()).is_none() {
            report.error("invalid-validator-goal", "validator goal is required");
        }
        if !is_allowed_validator_kind(validator.kind.as_str()) {
            report.error(
                "invalid-validator-kind",
                format!("unknown validator kind '{}'", validator.kind),
            );
        }
        match validator.kind.as_str() {
            "serial-log-pattern" if validator.pattern.as_deref().and_then(nonempty).is_none() => {
                report.error(
                    "validator-missing-pattern",
                    "serial-log-pattern validator requires a non-empty pattern",
                );
            }
            "process" if validator.name.as_deref().and_then(nonempty).is_none() => {
                report.error(
                    "validator-missing-name",
                    "process validator requires a non-empty name",
                );
            }
            "file-exists" if validator.path.as_deref().and_then(nonempty).is_none() => {
                report.error(
                    "validator-missing-path",
                    "file-exists validator requires a non-empty path",
                );
            }
            "listener" | "http" if validator.port.is_none() => {
                report.error(
                    "validator-missing-port",
                    format!("{} validator requires a port", validator.kind),
                );
            }
            _ => {}
        }
        if let Some(path) = validator.path.as_deref() {
            validate_guest_path(report, "invalid-validator-path", path);
        }
    }
}

/// A pack may only declare mutations if it also declares that its fixture is
/// modified. The invariant is fidelity, not provenance: a pack that quietly
/// alters the guest while presenting itself as an ordinary profile would make
/// every result obtained through it unattributable to the original firmware.
fn validate_fixture_mutations(pack: &RehostingPack, report: &mut RehostingPackValidationReport) {
    if pack.fixture_mutations.is_empty() {
        return;
    }

    if !pack.modified_fixture {
        report.error(
            "fixture-mutation-requires-modified-fixture",
            "fixture mutations are only valid when modified_fixture: true is set",
        );
    } else {
        report.warn(
            "modified-fixture-mutation",
            "pack mutates its fixture and must not be treated as a faithful emulation profile",
        );
    }

    for mutation in &pack.fixture_mutations {
        if nonempty(mutation.kind.as_str()).is_none() {
            report.error(
                "invalid-fixture-mutation-kind",
                "fixture mutation kind is required",
            );
        }
        if let Some(path) = mutation.path.as_deref() {
            validate_guest_path(report, "invalid-fixture-mutation-path", path);
        }
    }
}

fn validate_guest_path(report: &mut RehostingPackValidationReport, code: &str, path: &str) {
    if !path.starts_with('/') || path.contains("/../") || path.ends_with("/..") {
        report.error(
            code,
            format!("guest path must be absolute and normalized: '{path}'"),
        );
    }
}

fn is_allowed_validator_kind(kind: &str) -> bool {
    matches!(
        kind,
        "serial-log-pattern"
            | "process"
            | "http"
            | "listener"
            | "file-exists"
            | "surface-ready"
            | "manual"
    )
}

fn nonempty(value: &str) -> Option<&str> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}
