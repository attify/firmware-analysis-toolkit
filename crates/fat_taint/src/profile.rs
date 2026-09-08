//! Taint profile parsing and sink catalog loading.
//!
//! FAT compiles in exactly one set of models: `profiles/core.yaml`, whose
//! entries are specified by ISO C, POSIX, or FastCGI and therefore hold for any
//! binary that links them. Everything else — vendor config APIs, platform
//! conventions, product-specific input paths — is a claim about a particular
//! system and must be supplied as an explicit external profile.
//!
//! Nothing is selected from evidence. An import, a symbol, a directory name or
//! an environment variable never causes a profile to load: observing
//! `xmldbc_get` in a binary is a fact about that binary's interface, not
//! permission to adopt a vendor's taint semantics for the whole run.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

// ── Compile-time core models ────────────────────────────────────────────────

const PROFILE_CORE: &str = include_str!("../profiles/core.yaml");

// ── YAML schema ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct ProfileYaml {
    name: String,
    // There is deliberately no `detect` field. A profile cannot nominate
    // markers that would make FAT load it on its own; selection is the
    // operator's, and a `detect:` key in an external profile is ignored.
    #[serde(default)]
    sources: SourcesYaml,
    #[serde(default)]
    sinks: Vec<SinkYaml>,
    #[serde(default)]
    blockers: Vec<SourceYaml>,
}

#[derive(Debug, Default, Deserialize)]
struct SourcesYaml {
    #[serde(default)]
    primary: Vec<SourceYaml>,
    #[serde(default)]
    secondary: Vec<SourceYaml>,
}

#[derive(Debug, Deserialize)]
struct SourceYaml {
    name: String,
    #[allow(dead_code)]
    #[serde(default)]
    note: String,
    /// How taint arrives from this source — `return`, `buffer`, and so on.
    /// Optional; consumers that need one default to `return`.
    #[serde(default)]
    taint_kind: Option<String>,
}

#[derive(Debug, Deserialize)]
struct SinkYaml {
    name: String,
    #[serde(default)]
    arg: u8,
    #[serde(default)]
    note: String,
    #[serde(default)]
    category: Option<SinkCategory>,
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(rename_all = "kebab-case")]
enum SinkCategory {
    CommandExec,
    StringOverflow,
    ConfigWrite,
    ConfigRead,
}

impl SinkCategory {
    fn as_str(self) -> &'static str {
        match self {
            Self::CommandExec => "command-exec",
            Self::StringOverflow => "string-overflow",
            Self::ConfigWrite => "config-write",
            Self::ConfigRead => "config-read",
        }
    }
}

// ── Public API ──────────────────────────────────────────────────────────────

/// A symbol whose presence suggests a taint source, and how taint arrives.
///
/// Used by recon passes that only see a binary's strings and therefore cannot
/// prove a dataflow. Asserting that a name means "this reads request data" is
/// a per-target claim, so beyond the specified models below these come from an
/// operator-selected profile.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceHintModel {
    pub function: String,
    pub taint_kind: String,
}

/// A single entry in the sink catalog: function name → (dangerous_arg, category).
#[derive(Debug, Clone)]
pub struct SinkEntry {
    pub name: String,
    pub dangerous_arg: u8,
    pub category: String,
}

/// Where a catalog entry came from, so a finding can say whose model it used.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum CatalogProvenance {
    /// A model specified by ISO C, POSIX, or FastCGI.
    Core,
    /// A model supplied by an operator-selected external profile.
    ExternalProfile {
        name: String,
        path: String,
        sha256: String,
    },
}

impl CatalogProvenance {
    pub fn label(&self) -> String {
        match self {
            Self::Core => "core".to_string(),
            Self::ExternalProfile { name, path, .. } => format!("profile {name} ({path})"),
        }
    }
}

/// One validated read shared by execution, cache identity and saved evidence.
#[derive(Debug)]
pub struct ExternalTaintProfile {
    contents: String,
    profile: ProfileYaml,
    provenance: CatalogProvenance,
}

impl ExternalTaintProfile {
    pub fn load(path: &Path) -> Result<Self, String> {
        let contents = std::fs::read_to_string(path)
            .map_err(|error| format!("failed to read taint profile {}: {error}", path.display()))?;
        let profile = parse_profile(&contents)
            .map_err(|error| format!("invalid taint profile {}: {error}", path.display()))?;
        reject_core_redefinition(&profile)
            .map_err(|error| format!("invalid taint profile {}: {error}", path.display()))?;
        let provenance = CatalogProvenance::ExternalProfile {
            name: profile.name.clone(),
            path: path.display().to_string(),
            sha256: format!("{:x}", Sha256::digest(contents.as_bytes())),
        };
        Ok(Self {
            contents,
            profile,
            provenance,
        })
    }

    pub fn contents(&self) -> &str {
        &self.contents
    }

    pub fn provenance(&self) -> &CatalogProvenance {
        &self.provenance
    }

    /// Source hints this profile declares, primary first.
    pub fn source_hints(&self) -> Vec<SourceHintModel> {
        self.profile
            .sources
            .primary
            .iter()
            .chain(self.profile.sources.secondary.iter())
            .map(|source| SourceHintModel {
                function: source.name.clone(),
                taint_kind: source
                    .taint_kind
                    .clone()
                    .unwrap_or_else(|| "return".to_string()),
            })
            .collect()
    }

    /// Merge this validated profile with core hints without reading the file again.
    pub fn source_hints_with_core(&self) -> Vec<SourceHintModel> {
        let mut hints = core_source_hints();
        for hint in self.source_hints() {
            match hints.iter_mut().find(|core| core.function == hint.function) {
                Some(existing) => *existing = hint,
                None => hints.push(hint),
            }
        }
        hints
    }
}

/// The source hints FAT compiles in.
///
/// `getenv` is ISO C: it returns a string the process did not produce, so its
/// return value is externally influenced wherever it is linked. Platform
/// request-parameter getters are not here — which of those exist, and whether
/// a given one carries request data, is a claim about one target.
pub fn core_source_hints() -> Vec<SourceHintModel> {
    vec![SourceHintModel {
        function: "getenv".to_string(),
        taint_kind: "return".to_string(),
    }]
}

/// The core source hints plus those from one explicitly selected profile.
///
/// External profiles may add source hints; core names are reserved by the
/// shared profile loader and cannot be redefined.
pub fn load_source_hints_from_path(path: &Path) -> Result<Vec<SourceHintModel>, String> {
    let selected = ExternalTaintProfile::load(path)?;
    Ok(selected.source_hints_with_core())
}

/// The models FAT compiles in.
///
/// This is the whole catalog when no external profile is selected. It is not a
/// renamed bundle of the old vendor profiles: every entry names a published
/// specification for the argument position it claims.
pub fn core_sink_catalog() -> Vec<SinkEntry> {
    let mut entries: BTreeMap<String, SinkEntry> = BTreeMap::new();
    let core = parse_profile(PROFILE_CORE).expect("core.yaml is valid and compiled in");
    merge_profile(&core, &mut entries);
    entries.into_values().collect()
}

/// Load the core models plus one explicitly selected external profile.
///
/// The profile is named by path. FAT ships no profiles to select by name, and
/// it does not search for one: if the operator does not pass a path, analysis
/// runs on the core models alone.
pub fn load_sink_catalog_from_path(path: &Path) -> Result<Vec<SinkEntry>, String> {
    let selected = ExternalTaintProfile::load(path)?;

    let mut entries: BTreeMap<String, SinkEntry> = core_sink_catalog()
        .into_iter()
        .map(|entry| (entry.name.clone(), entry))
        .collect();

    merge_profile(&selected.profile, &mut entries);
    Ok(entries.into_values().collect())
}

/// An external profile may add models. It may not restate one core already
/// defines.
///
/// Core entries are argument-position facts fixed by a specification, so
/// "override `system` to take its command at argument 1" is not a preference
/// the operator is entitled to express — it contradicts ISO C. Adding new
/// names is the real use case, and it is unaffected.
///
/// This is an error rather than a silent drop because the two engines used to
/// resolve the collision in opposite directions: the Rust catalog kept the
/// core entry while the angr bridge kept the external one, so the same profile
/// produced different models depending on which path ran it. Refusing the
/// input is the only resolution that cannot diverge again.
fn reject_core_redefinition(profile: &ProfileYaml) -> Result<(), String> {
    let core = parse_profile(PROFILE_CORE).expect("core.yaml is valid and compiled in");
    let reserved: BTreeSet<&str> = profile_entry_names(&core).collect();
    let redefined: Vec<&str> = profile_entry_names(profile)
        .filter(|name| reserved.contains(*name))
        .collect();

    if redefined.is_empty() {
        return Ok(());
    }

    Err(format!(
        "taint profile {} redefines core model(s): {}. Core models are fixed by \
         specification and cannot be overridden; remove the entries or rename them.",
        profile.name,
        redefined.join(", ")
    ))
}

/// Every modeled name, including blockers that do not enter the sink catalog.
fn profile_entry_names(profile: &ProfileYaml) -> impl Iterator<Item = &str> {
    profile
        .sinks
        .iter()
        .map(|sink| sink.name.as_str())
        .chain(profile.sources.primary.iter().map(|src| src.name.as_str()))
        .chain(
            profile
                .sources
                .secondary
                .iter()
                .map(|src| src.name.as_str()),
        )
        .chain(profile.blockers.iter().map(|blocker| blocker.name.as_str()))
}

/// Provenance for a run, given the profile path the operator selected (if any).
pub fn catalog_provenance(path: Option<&Path>) -> Result<CatalogProvenance, String> {
    let Some(path) = path else {
        return Ok(CatalogProvenance::Core);
    };
    Ok(ExternalTaintProfile::load(path)?.provenance)
}

// ── Internals ───────────────────────────────────────────────────────────────

fn parse_profile(yaml: &str) -> Result<ProfileYaml, String> {
    serde_yaml::from_str(yaml).map_err(|e| e.to_string())
}

fn merge_profile(profile: &ProfileYaml, entries: &mut BTreeMap<String, SinkEntry>) {
    // Sinks
    for sink in &profile.sinks {
        entries
            .entry(sink.name.clone())
            .or_insert_with(|| SinkEntry {
                name: sink.name.clone(),
                dangerous_arg: sink.arg,
                // Older external profiles may omit the category. Core models
                // declare it explicitly so editing citations cannot change it.
                category: sink
                    .category
                    .map(|category| category.as_str().to_string())
                    .unwrap_or_else(|| infer_sink_category(&sink.note)),
            });
    }

    // Primary sources → input-source
    for src in &profile.sources.primary {
        entries
            .entry(src.name.clone())
            .or_insert_with(|| SinkEntry {
                name: src.name.clone(),
                dangerous_arg: 0,
                category: "input-source".to_string(),
            });
    }

    // Secondary sources → config-read
    for src in &profile.sources.secondary {
        entries
            .entry(src.name.clone())
            .or_insert_with(|| SinkEntry {
                name: src.name.clone(),
                dangerous_arg: 0,
                category: "config-read".to_string(),
            });
    }
}

fn infer_sink_category(note: &str) -> String {
    let lower = note.to_lowercase();
    if lower.contains("command execution")
        || lower.contains("execute binary")
        || lower.contains("system()")
        || lower.contains("os command")
    {
        "command-exec".to_string()
    } else if lower.contains("buffer")
        || lower.contains("overflow")
        || lower.contains("format string")
    {
        "string-overflow".to_string()
    } else if lower.contains("config write")
        || lower.contains("nvram write")
        || lower.contains("nvram persist")
    {
        "config-write".to_string()
    } else if lower.contains("config read") || lower.contains("nvram read") {
        "config-read".to_string()
    } else {
        // Default: vendor sinks that write state are typically config-write
        "config-write".to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn execution_categories_do_not_depend_on_specification_prose() {
        let entries = core_sink_catalog();
        for name in [
            "system", "popen", "execl", "execlp", "execv", "execve", "execvp",
        ] {
            assert_eq!(
                entries.iter().find(|e| e.name == name).unwrap().category,
                "command-exec",
                "{name}"
            );
        }
        let file = write_profile("name: example\nsinks:\n  - name: example_exec\n    category: command-exec\n    note: A documented platform operation\n");
        let selected = load_sink_catalog_from_path(file.path()).unwrap();
        assert_eq!(
            selected
                .iter()
                .find(|e| e.name == "example_exec")
                .unwrap()
                .category,
            "command-exec"
        );
    }

    fn write_profile(body: &str) -> tempfile::NamedTempFile {
        let mut file = tempfile::Builder::new()
            .suffix(".yaml")
            .tempfile()
            .expect("profile file");
        file.write_all(body.as_bytes()).expect("write profile");
        file.flush().expect("flush profile");
        file
    }

    const VENDOR_PROFILE: &str = r#"
name: example-platform
detect:
  - exec_shell_sync
sources:
  primary:
    - name: platform_get_query
      note: platform HTTP query getter
sinks:
  - name: exec_shell_sync
    arg: 0
    note: OS command execution
"#;

    #[test]
    fn the_core_catalog_carries_the_specified_models() {
        let entries = core_sink_catalog();
        for expected in [
            "system", "popen", "execve", "execvp", "sprintf", "strcpy", "strcat", "getenv", "read",
        ] {
            assert!(
                entries.iter().any(|entry| entry.name == expected),
                "core model {expected} is missing"
            );
        }
        assert_eq!(
            entries
                .iter()
                .find(|entry| entry.name == "system")
                .map(|entry| entry.dangerous_arg),
            Some(0)
        );
    }

    /// The core catalog is a set of specified models, not the old vendor union
    /// under a new name. These are the platform conventions it must not carry.
    #[test]
    fn the_core_catalog_carries_no_platform_convention_models() {
        let entries = core_sink_catalog();
        for unsupported in [
            "nvram_get",
            "nvram_set",
            "acosNvramConfig_get",
            "xmldbc_get",
            "cgibin_get_var",
            "websGetVar",
            "getcfg",
            "uci_get",
            "uci_set",
            "cgi_get",
            "web_get",
        ] {
            assert!(
                !entries.iter().any(|entry| entry.name == unsupported),
                "{unsupported} is a platform convention and must come from an external profile"
            );
        }
    }

    /// The central non-activation claim: a matching import used to pull in a
    /// whole vendor profile. Imports no longer select anything.
    #[test]
    fn an_import_never_selects_a_profile() {
        let file = write_profile(VENDOR_PROFILE);
        // The profile exists and its detect marker names a real function, but
        // nothing reads it unless it is selected by path.
        let entries = core_sink_catalog();
        assert!(
            !entries.iter().any(|entry| entry.name == "exec_shell_sync"),
            "an unselected profile must not contribute models"
        );
        drop(file);
    }

    #[test]
    fn an_explicitly_selected_profile_extends_the_core_models() {
        let file = write_profile(VENDOR_PROFILE);
        let entries = load_sink_catalog_from_path(file.path()).expect("profile loads");

        assert!(entries.iter().any(|entry| entry.name == "exec_shell_sync"));
        assert!(entries
            .iter()
            .any(|entry| entry.name == "platform_get_query"));
        // and the core models are still present
        assert!(entries.iter().any(|entry| entry.name == "system"));
    }

    #[test]
    fn a_detect_key_in_a_selected_profile_is_inert() {
        let file = write_profile(VENDOR_PROFILE);
        let selected = load_sink_catalog_from_path(file.path()).expect("profile loads");
        let core = core_sink_catalog();
        // The profile contributes because it was selected, not because its
        // detect marker matched anything.
        assert!(selected.len() > core.len());
    }

    #[test]
    fn a_missing_profile_is_an_error_not_a_silent_fallback() {
        let error = load_sink_catalog_from_path(Path::new("/nonexistent/profile.yaml"))
            .expect_err("a missing profile must fail");
        assert!(error.contains("failed to read taint profile"), "{error}");
    }

    #[test]
    fn a_malformed_profile_is_an_error_not_a_silent_fallback() {
        let file = write_profile("name: broken\nsinks: [oops\n");
        let error =
            load_sink_catalog_from_path(file.path()).expect_err("a malformed profile must fail");
        assert!(error.contains("invalid taint profile"), "{error}");
    }

    #[test]
    fn provenance_distinguishes_core_models_from_a_selected_profile() {
        assert_eq!(
            catalog_provenance(None).expect("core"),
            CatalogProvenance::Core
        );

        let file = write_profile(VENDOR_PROFILE);
        let provenance = catalog_provenance(Some(file.path())).expect("selected");
        assert!(provenance.label().starts_with("profile example-platform ("));
    }

    /// Core is authoritative. An external profile that restates a core model
    /// is refused, not silently resolved — silent resolution is what let the
    /// Rust catalog and the angr bridge disagree about `system`'s dangerous
    /// argument.
    #[test]
    fn an_external_profile_may_not_redefine_a_core_model() {
        let file = write_profile("name: example-platform\nsinks:\n  - name: system\n    arg: 1\n");
        let error = load_sink_catalog_from_path(file.path())
            .expect_err("redefining a core sink must be refused");
        assert!(error.contains("redefines core model(s): system"), "{error}");
    }

    #[test]
    fn every_public_profile_loader_rejects_core_names_in_every_role() {
        for name in ["getenv", "system", "crypt"] {
            for section in [
                "sources:\n  primary",
                "sources:\n  secondary",
                "sinks",
                "blockers",
            ] {
                let file = write_profile(&format!(
                    "name: example-platform\n{section}: [{{name: {name}}}]\n"
                ));
                let errors = [
                    ExternalTaintProfile::load(file.path()).unwrap_err(),
                    load_source_hints_from_path(file.path()).unwrap_err(),
                    load_sink_catalog_from_path(file.path()).unwrap_err(),
                    catalog_provenance(Some(file.path())).unwrap_err(),
                ];
                for error in errors {
                    assert!(
                        error.contains(&format!("redefines core model(s): {name}")),
                        "{section}: {error}"
                    );
                }
            }
        }
    }

    #[test]
    fn external_blockers_preserve_the_selected_bytes_and_identity() {
        let contents = "name: example-platform\nblockers: [{name: example_digest}]\n";
        let file = write_profile(contents);
        let selected = ExternalTaintProfile::load(file.path()).expect("new blocker is allowed");
        assert_eq!(selected.contents(), contents);
        assert_eq!(
            selected.provenance(),
            &CatalogProvenance::ExternalProfile {
                name: "example-platform".to_string(),
                path: file.path().display().to_string(),
                sha256: format!("{:x}", Sha256::digest(contents.as_bytes())),
            }
        );
    }

    /// The restriction is on restating core entries, not on adding new ones.
    #[test]
    fn an_external_profile_may_add_models_core_does_not_define() {
        let file = write_profile(
            "name: example-platform\nsources:\n  primary:\n    - name: nvram_get\nsinks:\n  - name: xmldbc_ep\n    arg: 0\n",
        );
        let catalog =
            load_sink_catalog_from_path(file.path()).expect("adding new models is allowed");
        let names: Vec<&str> = catalog.iter().map(|e| e.name.as_str()).collect();
        assert!(names.contains(&"nvram_get"), "{names:?}");
        assert!(names.contains(&"xmldbc_ep"), "{names:?}");
        // Core survives alongside them.
        assert!(names.contains(&"system"), "{names:?}");
    }
}
