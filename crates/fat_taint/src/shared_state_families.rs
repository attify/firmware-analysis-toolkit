//! Shared-state stitching machinery for cross-binary analysis.
//!
//! Two binaries form a chain when one writes a shared-state key that the other
//! reads and feeds to a sink. Deciding that `nvram_set` writes and `nvram_get`
//! reads is not a fact about either binary: it is a claim about a particular
//! platform's config API, in the same class as the vendor sink models that
//! [`crate::profile`] already refuses to compile in.
//!
//! So this module ships the *machinery* and no catalog. Function names are
//! matched against families an operator supplies as an external profile; with
//! no profile selected the catalog is empty, `classify` resolves nothing, and
//! cross-binary stitching produces no findings. Raw observed symbol names stay
//! available to the caller either way — not classifying a name is different
//! from hiding that the name was seen.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::path::Path;

/// A family of functions that read and write the same shared-state mechanism.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SharedStateFamily {
    pub id: String,
    pub write_patterns: Vec<String>,
    pub read_patterns: Vec<String>,
    /// Flush operations commit state but do NOT accept attacker-controlled
    /// input. Excluded from write classification.
    pub flush_patterns: Vec<String>,
}

impl SharedStateFamily {
    /// Apply this family's read/write roles and flush exclusions to observed text.
    /// Shared by binary findings and the strings provider so exclusions agree.
    pub fn classify(&self, function_name: &str) -> Option<OpDirection> {
        let matches = |patterns: &[String]| {
            patterns
                .iter()
                .any(|pattern| function_name.contains(pattern.as_str()))
        };
        if matches(&self.flush_patterns) {
            None
        } else if matches(&self.write_patterns) {
            Some(OpDirection::Write)
        } else if matches(&self.read_patterns) {
            Some(OpDirection::Read)
        } else {
            None
        }
    }
}

/// Direction of a shared-state operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum OpDirection {
    Write,
    Read,
}

/// Where the families used by a run came from.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SharedStateProvenance {
    /// No profile was selected, so no function name carries a role.
    Unset,
    /// Families supplied by an operator-selected external profile.
    ExternalProfile {
        name: String,
        path: String,
        sha256: String,
    },
}

impl SharedStateProvenance {
    pub fn label(&self) -> String {
        match self {
            Self::Unset => "none (no shared-state profile selected)".to_string(),
            Self::ExternalProfile { name, path, .. } => format!("profile {name} ({path})"),
        }
    }
}

// ── YAML schema ─────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct ProfileYaml {
    name: String,
    #[serde(default)]
    families: Vec<FamilyYaml>,
}

#[derive(Debug, Deserialize)]
struct FamilyYaml {
    id: String,
    #[serde(default)]
    write: Vec<String>,
    #[serde(default)]
    read: Vec<String>,
    #[serde(default)]
    flush: Vec<String>,
}

// ── Catalog ─────────────────────────────────────────────────────────────────

/// The families in force for one run, plus where they came from.
///
/// [`SharedStateCatalog::empty`] is the default: FAT compiles in no families,
/// and nothing — an import, a symbol, a directory name — selects one.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SharedStateCatalog {
    families: Vec<SharedStateFamily>,
    provenance: SharedStateProvenance,
}

impl Default for SharedStateCatalog {
    fn default() -> Self {
        Self::empty()
    }
}

impl SharedStateCatalog {
    /// The catalog used when the operator selects no profile: no families.
    pub fn empty() -> Self {
        Self {
            families: Vec::new(),
            provenance: SharedStateProvenance::Unset,
        }
    }

    /// Load families from an operator-supplied profile, by path.
    ///
    /// The path is the whole selection mechanism. There is no name lookup and
    /// no search path, so a profile cannot be picked up from the analysed
    /// firmware or from an install directory.
    pub fn load(path: &Path) -> Result<Self, String> {
        let contents = std::fs::read_to_string(path).map_err(|error| {
            format!(
                "failed to read shared-state profile {}: {error}",
                path.display()
            )
        })?;
        let parsed = parse_profile(&contents)
            .map_err(|error| format!("invalid shared-state profile {}: {error}", path.display()))?;

        let families = parsed
            .families
            .into_iter()
            .map(|family| SharedStateFamily {
                id: family.id,
                write_patterns: family.write,
                read_patterns: family.read,
                flush_patterns: family.flush,
            })
            .collect();

        Ok(Self {
            families,
            provenance: SharedStateProvenance::ExternalProfile {
                name: parsed.name,
                path: path.display().to_string(),
                sha256: format!("{:x}", Sha256::digest(contents.as_bytes())),
            },
        })
    }

    pub fn is_empty(&self) -> bool {
        self.families.is_empty()
    }

    pub fn families(&self) -> &[SharedStateFamily] {
        &self.families
    }

    pub fn provenance(&self) -> &SharedStateProvenance {
        &self.provenance
    }

    /// Resolve a function name to its family and direction.
    ///
    /// Returns `None` for flush operations, for unrecognized functions, and —
    /// always — when no profile is selected.
    pub fn classify(&self, function_name: &str) -> Option<(&SharedStateFamily, OpDirection)> {
        self.families.iter().find_map(|family| {
            family
                .classify(function_name)
                .map(|direction| (family, direction))
        })
    }
}

/// Whether a write and a read may be stitched into one cross-binary chain.
///
/// A `None` family is an observation whose role the selected profile did not
/// resolve. It may pair with any family that profile declares, because the
/// operator asserted those families exist on this target; two unresolved
/// observations never pair with each other, since nothing connects them.
pub fn families_match(write_family: Option<&str>, read_family: Option<&str>) -> bool {
    match (write_family, read_family) {
        (Some(write), Some(read)) => write == read,
        (Some(_), None) | (None, Some(_)) => true,
        (None, None) => false,
    }
}

fn parse_profile(yaml: &str) -> Result<ProfileYaml, String> {
    let profile: ProfileYaml = serde_yaml::from_str(yaml).map_err(|e| e.to_string())?;
    if profile.name.trim().is_empty() {
        return Err("shared-state profile is missing a name".to_string());
    }
    let mut ids = std::collections::BTreeSet::new();
    for family in &profile.families {
        if family.id.trim().is_empty() {
            return Err("shared-state family is missing an id".to_string());
        }
        if !ids.insert(&family.id) {
            return Err(format!("duplicate shared-state family id: {}", family.id));
        }
        if family
            .read
            .iter()
            .chain(&family.write)
            .chain(&family.flush)
            .any(|pattern| pattern.trim().is_empty())
        {
            return Err(format!(
                "shared-state family '{}' has a blank function pattern",
                family.id
            ));
        }
        if family.read.is_empty() && family.write.is_empty() {
            return Err(format!(
                "shared-state family '{}' declares no read or write functions",
                family.id
            ));
        }
    }
    Ok(profile)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn review_rejects_blank_patterns_and_duplicate_family_ids() {
        for yaml in [
            "name: test\nfamilies:\n  - id: store\n    write: ['']\n",
            "name: test\nfamilies:\n  - id: store\n    read: ['  ']\n",
            "name: test\nfamilies:\n  - id: store\n    read: [get]\n    flush: ['']\n",
            "name: test\nfamilies:\n  - id: store\n    write: [set_a]\n  - id: store\n    read: [get_b]\n",
        ] {
            assert!(parse_profile(yaml).is_err(), "accepted ambiguous profile: {yaml}");
        }
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

    const EXAMPLE_PROFILE: &str = r#"
name: example-platform
families:
  - id: example-store
    write: [example_store_set]
    read: [example_store_get]
    flush: [example_store_commit]
"#;

    /// The central non-activation claim for this consumer: with no profile
    /// selected, no function name carries a read or write role.
    #[test]
    fn an_unselected_catalog_classifies_nothing() {
        let catalog = SharedStateCatalog::empty();
        assert!(catalog.is_empty());
        for name in [
            "nvram_set",
            "nvram_get",
            "nvram_bufset",
            "acosNvramConfig_get",
            "Set_Private_Profile_String",
            "Get_Private_Profile_String",
            "getcfg",
            "setcfg",
            "uci_get",
            "uci_set",
            "system",
        ] {
            assert!(
                catalog.classify(name).is_none(),
                "{name} was classified without a selected profile"
            );
        }
        assert_eq!(catalog.provenance(), &SharedStateProvenance::Unset);
    }

    #[test]
    fn a_selected_profile_supplies_the_families() {
        let file = write_profile(EXAMPLE_PROFILE);
        let catalog = SharedStateCatalog::load(file.path()).expect("profile loads");

        let (family, direction) = catalog.classify("example_store_set").expect("write");
        assert_eq!(family.id, "example-store");
        assert_eq!(direction, OpDirection::Write);

        let (family, direction) = catalog.classify("example_store_get").expect("read");
        assert_eq!(family.id, "example-store");
        assert_eq!(direction, OpDirection::Read);
    }

    #[test]
    fn substring_matching_still_resolves_decorated_symbol_names() {
        let file = write_profile(EXAMPLE_PROFILE);
        let catalog = SharedStateCatalog::load(file.path()).expect("profile loads");
        let (_, direction) = catalog
            .classify("sym.imp.example_store_get")
            .expect("decorated read");
        assert_eq!(direction, OpDirection::Read);
    }

    #[test]
    fn flush_functions_are_not_writes() {
        let file = write_profile(EXAMPLE_PROFILE);
        let catalog = SharedStateCatalog::load(file.path()).expect("profile loads");
        assert!(catalog.classify("example_store_commit").is_none());
    }

    #[test]
    fn provenance_records_the_selected_path_and_digest() {
        let file = write_profile(EXAMPLE_PROFILE);
        let catalog = SharedStateCatalog::load(file.path()).expect("profile loads");
        match catalog.provenance() {
            SharedStateProvenance::ExternalProfile { name, path, sha256 } => {
                assert_eq!(name, "example-platform");
                assert_eq!(path, &file.path().display().to_string());
                assert_eq!(sha256.len(), 64);
            }
            other => panic!("expected external provenance, got {other:?}"),
        }
    }

    #[test]
    fn a_missing_profile_is_an_error_not_a_silent_fallback() {
        let error = SharedStateCatalog::load(Path::new("/nonexistent/state.yaml")).unwrap_err();
        assert!(
            error.contains("failed to read shared-state profile"),
            "{error}"
        );
    }

    #[test]
    fn a_family_with_no_functions_is_rejected() {
        let file = write_profile("name: bad\nfamilies:\n  - id: empty\n");
        let error = SharedStateCatalog::load(file.path()).unwrap_err();
        assert!(
            error.contains("declares no read or write functions"),
            "{error}"
        );
    }

    #[test]
    fn families_match_same_and_reject_different() {
        assert!(families_match(Some("example-store"), Some("example-store")));
        assert!(!families_match(Some("example-store"), Some("other-store")));
    }

    #[test]
    fn an_unresolved_observation_pairs_with_a_declared_family_but_not_with_itself() {
        assert!(families_match(Some("example-store"), None));
        assert!(families_match(None, Some("example-store")));
        assert!(!families_match(None, None));
    }
}
