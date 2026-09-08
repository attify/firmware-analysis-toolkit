//! Consistency checks over the checked-in maintained-kernel profiles.
//!
//! A maintained catalog entry names the machine profile its artifact has to run
//! on. The recipe that produced that artifact separately names the machine
//! profiles it targets. Nothing in the build compares the two, so they can drift
//! apart silently -- and when they do, the artifact becomes unusable: the
//! catalog demands a QEMU the recipe never targeted, `fat emulate` refuses the
//! kernel, and the failure looks like a host problem rather than a data problem.
//!
//! These tests read the real `profiles/kernels` tree, not a fixture, because the
//! thing being protected is the shipped data.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde_json::Value;

fn profiles_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join("profiles")
        .join("kernels")
}

fn read_json(path: &Path) -> Value {
    let text = fs::read_to_string(path)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", path.display()));
    serde_json::from_str(&text)
        .unwrap_or_else(|error| panic!("failed to parse {}: {error}", path.display()))
}

fn read_dir_json(dir: &Path) -> Vec<(PathBuf, Value)> {
    let mut entries = fs::read_dir(dir)
        .unwrap_or_else(|error| panic!("failed to read {}: {error}", dir.display()))
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect::<Vec<_>>();
    entries.sort();
    entries
        .into_iter()
        .map(|path| {
            let value = read_json(&path);
            (path, value)
        })
        .collect()
}

/// Recipes keyed by the compatibility class they build for.
fn recipes_by_class() -> BTreeMap<String, Value> {
    read_dir_json(&profiles_root().join("recipes"))
        .into_iter()
        .map(|(path, value)| {
            let class = value["class"]
                .as_str()
                .unwrap_or_else(|| panic!("{} has no class", path.display()))
                .to_string();
            (class, value)
        })
        .collect()
}

fn machines_by_id() -> BTreeMap<String, Value> {
    read_dir_json(&profiles_root().join("machines"))
        .into_iter()
        .map(|(path, value)| {
            let id = value["id"]
                .as_str()
                .unwrap_or_else(|| panic!("{} has no id", path.display()))
                .to_string();
            (id, value)
        })
        .collect()
}

/// Catalog entries that FAT builds itself. The other entries describe kernels an
/// operator supplies externally and carry no compatibility class.
fn maintained_catalog_entries() -> Vec<Value> {
    let catalog = read_json(&profiles_root().join("catalog.json"));
    catalog
        .as_array()
        .expect("catalog.json must be an array")
        .iter()
        .filter(|entry| entry.get("compatibility_class").is_some())
        .cloned()
        .collect()
}

#[test]
fn maintained_entries_require_a_machine_profile_their_recipe_declares() {
    let recipes = recipes_by_class();
    let mut drift = Vec::new();

    for entry in maintained_catalog_entries() {
        let class = entry["compatibility_class"].as_str().unwrap();
        let required = entry["required_machine_profile"].as_str().unwrap_or("");
        let Some(recipe) = recipes.get(class) else {
            drift.push(format!("class {class} has a catalog entry but no recipe"));
            continue;
        };
        let declared = recipe["machine_profile_ids"]
            .as_array()
            .map(|ids| {
                ids.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if !declared.iter().any(|id| id == required) {
            drift.push(format!(
                "class {class}: catalog requires {required}, recipe declares {declared:?}"
            ));
        }
    }

    assert!(
        drift.is_empty(),
        "catalog and recipes disagree about machine profiles:\n  {}",
        drift.join("\n  ")
    );
}

// The catalog carries the validated set that host-aware selection chooses from.
// If it falls behind the recipe, a host running a validated QEMU silently loses
// the profile that would have served it.
#[test]
fn maintained_entries_publish_the_full_validated_set_from_their_recipe() {
    let recipes = recipes_by_class();
    let mut drift = Vec::new();

    for entry in maintained_catalog_entries() {
        let class = entry["compatibility_class"].as_str().unwrap();
        let published = entry["compatible_machine_profiles"]
            .as_array()
            .map(|ids| {
                ids.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        let declared = recipes
            .get(class)
            .and_then(|recipe| recipe["machine_profile_ids"].as_array())
            .map(|ids| {
                ids.iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect::<BTreeSet<_>>()
            })
            .unwrap_or_default();
        if published != declared {
            drift.push(format!(
                "class {class}: catalog publishes {published:?}, recipe declares {declared:?}"
            ));
        }
    }

    assert!(
        drift.is_empty(),
        "catalog validated sets are out of step with the recipes:\n  {}",
        drift.join("\n  ")
    );
}

#[test]
fn required_machine_profiles_exist_and_serve_their_class() {
    let machines = machines_by_id();
    let mut problems = Vec::new();

    for entry in maintained_catalog_entries() {
        let class = entry["compatibility_class"].as_str().unwrap();
        let required = entry["required_machine_profile"].as_str().unwrap_or("");
        let Some(machine) = machines.get(required) else {
            problems.push(format!(
                "class {class} requires machine profile {required}, which is not on disk"
            ));
            continue;
        };
        let serves = machine["classes"]
            .as_array()
            .map(|classes| classes.iter().filter_map(Value::as_str).any(|c| c == class))
            .unwrap_or(false);
        if !serves {
            problems.push(format!(
                "machine profile {required} does not declare class {class}"
            ));
        }
    }

    assert!(
        problems.is_empty(),
        "machine profile requirements are unsatisfiable:\n  {}",
        problems.join("\n  ")
    );
}

#[test]
fn every_recipe_declares_at_least_one_machine_profile_that_exists() {
    let machines = machines_by_id();
    let mut problems = Vec::new();

    for (class, recipe) in recipes_by_class() {
        let declared = recipe["machine_profile_ids"]
            .as_array()
            .map(|ids| ids.iter().filter_map(Value::as_str).collect::<Vec<_>>())
            .unwrap_or_default();
        if declared.is_empty() {
            problems.push(format!("recipe for {class} declares no machine profile"));
            continue;
        }
        for id in declared {
            if !machines.contains_key(id) {
                problems.push(format!("recipe for {class} names unknown machine {id}"));
            }
        }
    }

    assert!(
        problems.is_empty(),
        "recipes reference machine profiles that do not exist:\n  {}",
        problems.join("\n  ")
    );
}
