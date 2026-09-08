//! Shell taint profile parsing (`profiles/shell-*.yaml`).
//!
//! These profiles mirror the shape of the ELF-side `profiles/core.yaml`
//! (`name` / `description` / `sources.primary` / `sources.secondary`) but the
//! entries describe shell constructs rather than libc symbols. Sinks are not
//! redefined here: each profile names one or more embedded sink profiles from
//! `sink_profiles/`, so shell taint and `fat sink-discovery --rootfs` agree on
//! what a dangerous shell construct is.
//!
//! `shell-base.yaml` is compile-embedded and always loaded, so every entry in
//! it must hold for any POSIX shell script. Target-dependent claims — this
//! platform's config helper, this device's attacker-writable mount — come from
//! an overlay the operator passes by path. The base profile therefore declares
//! no writable paths at all: a path prefix on its own never establishes
//! attacker control, so an unqualified read stays Secondary until an overlay
//! says otherwise.

use serde::{Deserialize, Serialize};
use std::path::Path;

use crate::sink_discovery::{parse_sink_profile, SinkProfile, SHELL_COMMAND_EXEC_PROFILE_YAML};

/// Always-loaded shell source profile.
pub const SHELL_BASE_PROFILE_YAML: &str = include_str!("../profiles/shell-base.yaml");

/// Embedded sink profiles a shell source profile may reference by name.
const SHELL_SINK_PROFILES: &[(&str, &str)] =
    &[("shell-command-exec", SHELL_COMMAND_EXEC_PROFILE_YAML)];

/// How a source manifests in a shell script.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ShellSourceKind {
    /// A command whose stdout is attacker-influenced (`cat`, `uci get`, ...).
    Command,
    /// `$1..$N` script arguments.
    Positional,
    /// Inherited environment variables named in `vars`.
    Environment,
    /// Literal paths under an attacker-writable mount named in `paths`.
    PathPrefix,
}

/// One source entry from a shell profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellSourceDef {
    pub name: String,
    pub kind: ShellSourceKind,
    /// Required argv prefix for `kind: command` (e.g. `[get]` for `uci get`).
    #[serde(default)]
    pub argv: Vec<String>,
    /// Environment variable names for `kind: environment`.
    #[serde(default)]
    pub vars: Vec<String>,
    /// Writable path prefixes for `kind: path-prefix`.
    #[serde(default)]
    pub paths: Vec<String>,
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellSources {
    #[serde(default)]
    pub primary: Vec<ShellSourceDef>,
    #[serde(default)]
    pub secondary: Vec<ShellSourceDef>,
}

/// A parsed shell taint profile.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellTaintProfile {
    pub name: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub sink_profiles: Vec<String>,
    #[serde(default)]
    pub sources: ShellSources,
}

impl ShellTaintProfile {
    /// Every source definition, primary first.
    pub fn all_sources(&self) -> impl Iterator<Item = (&ShellSourceDef, bool)> {
        self.sources
            .primary
            .iter()
            .map(|def| (def, true))
            .chain(self.sources.secondary.iter().map(|def| (def, false)))
    }
}

/// Parse one shell profile YAML document.
pub fn parse_shell_profile(yaml: &str) -> Result<ShellTaintProfile, String> {
    let profile: ShellTaintProfile = serde_yaml::from_str(yaml).map_err(|e| e.to_string())?;
    if profile.name.trim().is_empty() {
        return Err("shell profile is missing a name".to_string());
    }
    if let Some(target) = &profile.target {
        if target != "shell" {
            return Err(format!(
                "shell profile '{}' declares target '{target}', expected 'shell'",
                profile.name
            ));
        }
    }
    for (def, _) in profile.all_sources() {
        match def.kind {
            ShellSourceKind::Environment if def.vars.is_empty() => {
                return Err(format!(
                    "shell profile '{}': source '{}' has kind environment but no vars",
                    profile.name, def.name
                ));
            }
            ShellSourceKind::PathPrefix if def.paths.is_empty() => {
                return Err(format!(
                    "shell profile '{}': source '{}' has kind path-prefix but no paths",
                    profile.name, def.name
                ));
            }
            _ => {}
        }
    }
    Ok(profile)
}

/// Load `shell-base.yaml`, optionally merging an operator-selected overlay.
///
/// Overlay entries replace base entries with the same `name`; new entries are
/// appended. FAT ships no overlays: the overlay is a path the operator gives,
/// and with none given the shell analysis runs on the base profile alone.
pub fn load_shell_profile(overlay: Option<&Path>) -> Result<ShellTaintProfile, String> {
    let mut profile = parse_shell_profile(SHELL_BASE_PROFILE_YAML)
        .map_err(|e| format!("shell-base.yaml: {e}"))?;

    let Some(overlay_path) = overlay else {
        return Ok(profile);
    };

    let yaml = std::fs::read_to_string(overlay_path).map_err(|error| {
        format!(
            "failed to read shell source profile {}: {error}",
            overlay_path.display()
        )
    })?;
    let overlay_profile = parse_shell_profile(&yaml).map_err(|error| {
        format!(
            "invalid shell source profile {}: {error}",
            overlay_path.display()
        )
    })?;

    merge_sources(
        &mut profile.sources.primary,
        &overlay_profile.sources.primary,
    );
    merge_sources(
        &mut profile.sources.secondary,
        &overlay_profile.sources.secondary,
    );
    for sink_profile in overlay_profile.sink_profiles {
        if !profile.sink_profiles.contains(&sink_profile) {
            profile.sink_profiles.push(sink_profile);
        }
    }
    profile.name = format!("{}+{}", profile.name, overlay_profile.name);
    Ok(profile)
}

fn merge_sources(base: &mut Vec<ShellSourceDef>, overlay: &[ShellSourceDef]) {
    for def in overlay {
        match base.iter_mut().find(|existing| existing.name == def.name) {
            Some(existing) => *existing = def.clone(),
            None => base.push(def.clone()),
        }
    }
}

/// Resolve the sink profiles a shell profile names into parsed [`SinkProfile`]s.
pub fn load_shell_sink_profiles(profile: &ShellTaintProfile) -> Result<Vec<SinkProfile>, String> {
    let mut out = Vec::new();
    for name in &profile.sink_profiles {
        let yaml = SHELL_SINK_PROFILES
            .iter()
            .find(|(known, _)| known == name)
            .map(|(_, yaml)| *yaml)
            .ok_or_else(|| {
                let known: Vec<&str> = SHELL_SINK_PROFILES.iter().map(|(n, _)| *n).collect();
                format!(
                    "shell profile '{}' references unknown sink profile '{name}'; available: {}",
                    profile.name,
                    known.join(", ")
                )
            })?;
        out.push(parse_sink_profile(yaml).map_err(|e| format!("{name}.yaml: {e}"))?);
    }
    if out.is_empty() {
        return Err(format!(
            "shell profile '{}' names no sink profiles; nothing to match against",
            profile.name
        ));
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base_profile_parses_with_expected_sources() {
        let profile = load_shell_profile(None).unwrap();
        assert_eq!(profile.name, "shell-base");
        assert_eq!(profile.target.as_deref(), Some("shell"));
        assert!(profile
            .sources
            .primary
            .iter()
            .any(|d| d.kind == ShellSourceKind::Positional));
        assert!(profile
            .sources
            .primary
            .iter()
            .any(|d| d.name == "environment" && d.vars.iter().any(|v| v == "QUERY_STRING")));
        assert!(profile
            .sources
            .secondary
            .iter()
            .any(|d| d.name == "uci" && d.argv == ["get"]));
    }

    #[test]
    fn base_profile_names_the_shared_shell_sink_profile() {
        let profile = load_shell_profile(None).unwrap();
        assert_eq!(
            profile.sink_profiles,
            vec!["shell-command-exec".to_string()]
        );
        let sinks = load_shell_sink_profiles(&profile).unwrap();
        assert_eq!(sinks.len(), 1);
        assert!(sinks[0].families.contains_key("sed-var-injection"));
    }

    /// The base profile asserts nothing about any device's filesystem. Naming
    /// a path does not make it attacker-writable, so the always-loaded profile
    /// declares no `path-prefix` source and no path at all.
    #[test]
    fn the_base_profile_declares_no_writable_paths() {
        let profile = load_shell_profile(None).unwrap();
        for (def, _) in profile.all_sources() {
            assert_ne!(
                def.kind,
                ShellSourceKind::PathPrefix,
                "base profile declares a writable path source: {}",
                def.name
            );
            assert!(
                def.paths.is_empty(),
                "base profile declares paths for {}",
                def.name
            );
        }
    }

    /// Each retained base entry names a specification or a publicly documented
    /// tool in its note. Entries whose support was only a platform convention
    /// were moved out to overlays.
    #[test]
    fn every_base_entry_documents_the_contract_that_supports_it() {
        let profile = load_shell_profile(None).unwrap();
        for (def, _) in profile.all_sources() {
            let note = def.note.to_ascii_lowercase();
            assert!(
                ["posix", "rfc 3875", "openwrt", "u-boot", "android"]
                    .iter()
                    .any(|marker| note.contains(marker)),
                "base source '{}' cites no supporting contract: {:?}",
                def.name,
                def.note
            );
        }
        for unsupported in ["nvram_get", "nvram"] {
            assert!(
                !profile
                    .all_sources()
                    .any(|(def, _)| def.name == unsupported),
                "{unsupported} is a platform convention and belongs in an overlay"
            );
        }
    }

    /// The overlay mechanism is unchanged; what changed is that FAT no longer
    /// ships overlays to select by name. A profile the operator supplies still
    /// replaces matching base entries and appends new ones — including the
    /// writable-mount assertion the base profile deliberately omits.
    #[test]
    fn a_supplied_overlay_replaces_matching_entries_and_appends_new_ones() {
        use std::io::Write;

        let base = load_shell_profile(None).unwrap();
        let base_cat = base
            .sources
            .secondary
            .iter()
            .find(|d| d.name == "cat")
            .unwrap()
            .clone();
        assert!(base_cat.argv.is_empty());

        let mut overlay = tempfile::Builder::new().suffix(".yaml").tempfile().unwrap();
        overlay
            .write_all(
                br#"
name: shell-example
sources:
  primary:
    - name: writable-mount-read
      kind: path-prefix
      paths: ["/params/"]
  secondary:
    - name: cat
      kind: command
      argv: [-v]
    - name: paracfg
      kind: command
"#,
            )
            .unwrap();
        overlay.flush().unwrap();

        let merged = load_shell_profile(Some(overlay.path())).unwrap();
        assert_eq!(merged.name, "shell-base+shell-example");
        // The overlay supplies the writable mount the base profile does not.
        let merged_writable = merged
            .sources
            .primary
            .iter()
            .find(|d| d.name == "writable-mount-read")
            .unwrap();
        assert!(merged_writable.paths.iter().any(|p| p == "/params/"));
        // A matching base entry is replaced.
        let merged_cat = merged
            .sources
            .secondary
            .iter()
            .find(|d| d.name == "cat")
            .unwrap();
        assert_eq!(merged_cat.argv, ["-v"]);
        // Untouched base entries survive the merge.
        assert!(merged.sources.secondary.iter().any(|d| d.name == "uci"));
        // New overlay entries are appended.
        assert!(merged.sources.secondary.iter().any(|d| d.name == "paracfg"));
    }

    #[test]
    fn a_missing_overlay_is_an_error_not_a_silent_fallback() {
        let err = load_shell_profile(Some(Path::new("/nonexistent/overlay.yaml"))).unwrap_err();
        assert!(err.contains("failed to read shell source profile"), "{err}");
    }

    #[test]
    fn environment_source_without_vars_is_rejected() {
        let yaml = "name: bad\nsources:\n  primary:\n    - name: env\n      kind: environment\n";
        let err = parse_shell_profile(yaml).unwrap_err();
        assert!(err.contains("kind environment but no vars"), "{err}");
    }

    #[test]
    fn path_prefix_source_without_paths_is_rejected() {
        let yaml = "name: bad\nsources:\n  primary:\n    - name: w\n      kind: path-prefix\n";
        let err = parse_shell_profile(yaml).unwrap_err();
        assert!(err.contains("kind path-prefix but no paths"), "{err}");
    }

    #[test]
    fn non_shell_target_is_rejected() {
        let yaml = "name: bad\ntarget: elf\n";
        let err = parse_shell_profile(yaml).unwrap_err();
        assert!(err.contains("declares target 'elf'"), "{err}");
    }
}
