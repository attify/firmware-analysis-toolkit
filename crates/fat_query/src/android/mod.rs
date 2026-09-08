pub mod benchmark;
pub mod chains;
pub mod discovery;
pub mod extractor;
pub mod families;
pub mod flutter_runtime;
pub mod graph;
pub mod handoff;
pub mod locality;
pub mod manifest;
pub mod native;
pub mod protocols;
pub mod resources;
pub mod revelations;
pub mod semantic;
pub mod subsystems;

use crate::android::semantic::{
    AndroidControlSurface, AndroidCorrelation, AndroidExtractorMetadata, AndroidNativeSemantic,
    AndroidRevelation, AndroidSemanticBundle, AndroidSemanticFact, AndroidSemanticTarget,
    AndroidSupportLevel,
};
use std::collections::BTreeSet;

pub(crate) fn derive_revelations(bundle: &AndroidSemanticBundle) -> AndroidSemanticBundle {
    let mut derived = empty_bundle();
    merge_semantics(
        &mut derived,
        revelations::commissioning::derive_commissioning_revelations(bundle),
    );
    merge_semantics(
        &mut derived,
        revelations::fabric::derive_fabric_revelations(bundle),
    );
    merge_semantics(
        &mut derived,
        revelations::key_lifecycle::derive_key_lifecycle_revelations(bundle),
    );
    merge_semantics(
        &mut derived,
        revelations::identity_translation::derive_identity_translation_revelations(bundle),
    );
    merge_semantics(
        &mut derived,
        revelations::native_boundary::derive_native_boundary_revelations(bundle),
    );
    merge_semantics(
        &mut derived,
        revelations::control_plane::derive_control_plane_revelations(bundle),
    );
    attach_revelation_subsystem_ids(bundle, &mut derived);
    derived
}

pub(crate) fn fact_ids_where<F>(bundle: &AndroidSemanticBundle, mut predicate: F) -> Vec<String>
where
    F: FnMut(&AndroidSemanticFact) -> bool,
{
    bundle
        .facts
        .iter()
        .filter(|fact| predicate(fact))
        .map(|fact| fact.fact_id.clone())
        .collect()
}

pub(crate) fn control_surface_ids_where<F>(
    bundle: &AndroidSemanticBundle,
    mut predicate: F,
) -> Vec<String>
where
    F: FnMut(&AndroidControlSurface) -> bool,
{
    bundle
        .control_surfaces
        .iter()
        .filter(|surface| predicate(surface))
        .map(|surface| surface.surface_id.clone())
        .collect()
}

pub(crate) fn native_ids_where<F>(bundle: &AndroidSemanticBundle, mut predicate: F) -> Vec<String>
where
    F: FnMut(&AndroidNativeSemantic) -> bool,
{
    bundle
        .native_semantics
        .iter()
        .filter(|native| predicate(native))
        .map(|native| native.native_id.clone())
        .collect()
}

pub(crate) fn correlation_ids_where<F>(
    bundle: &AndroidSemanticBundle,
    mut predicate: F,
) -> Vec<String>
where
    F: FnMut(&AndroidCorrelation) -> bool,
{
    bundle
        .correlations
        .iter()
        .filter(|correlation| predicate(correlation))
        .map(|correlation| correlation.correlation_id.clone())
        .collect()
}

fn merge_semantics(into: &mut AndroidSemanticBundle, other: AndroidSemanticBundle) {
    into.facts.extend(other.facts);
    into.symbol_identities.extend(other.symbol_identities);
    into.control_surfaces.extend(other.control_surfaces);
    into.transport_surfaces.extend(other.transport_surfaces);
    into.trust_boundaries.extend(other.trust_boundaries);
    into.resources.extend(other.resources);
    into.native_semantics.extend(other.native_semantics);
    into.subsystems.extend(other.subsystems);
    into.revelations.extend(other.revelations);
    into.correlations.extend(other.correlations);
    into.warnings.extend(other.warnings);
}

pub(crate) fn empty_bundle() -> AndroidSemanticBundle {
    AndroidSemanticBundle {
        bundle_version: String::new(),
        target: AndroidSemanticTarget {
            application_id: None,
            package_name: String::new(),
            version_code: None,
            version_name: None,
            split_names: Vec::new(),
        },
        extractor: AndroidExtractorMetadata {
            extractor_id: String::new(),
            extractor_version: String::new(),
            input_kind: String::new(),
            generated_at_utc: None,
            degraded: false,
            notes: Vec::new(),
        },
        facts: Vec::new(),
        symbol_identities: Vec::new(),
        control_surfaces: Vec::new(),
        transport_surfaces: Vec::new(),
        trust_boundaries: Vec::new(),
        resources: Vec::new(),
        native_semantics: Vec::new(),
        subsystems: Vec::new(),
        revelations: Vec::new(),
        correlations: Vec::new(),
        warnings: Vec::new(),
    }
}

pub(crate) fn revelation(
    revelation_id: &str,
    kind: &str,
    members: Vec<String>,
    rationale: &str,
) -> AndroidRevelation {
    AndroidRevelation {
        revelation_id: revelation_id.into(),
        kind: kind.into(),
        support_level: AndroidSupportLevel::Inferred,
        members,
        subsystem_ids: Vec::new(),
        rationale: Some(rationale.into()),
    }
}

pub(crate) fn dedupe_strings(values: Vec<String>) -> Vec<String> {
    let mut seen = BTreeSet::new();
    values
        .into_iter()
        .filter(|value| seen.insert(value.clone()))
        .collect()
}

fn attach_revelation_subsystem_ids(
    source_bundle: &AndroidSemanticBundle,
    derived: &mut AndroidSemanticBundle,
) {
    for revelation in &mut derived.revelations {
        if !revelation.subsystem_ids.is_empty() {
            continue;
        }
        let mut scored_matches: Vec<(usize, String)> = source_bundle
            .subsystems
            .iter()
            .filter_map(|subsystem| {
                let score = revelation_subsystem_score(revelation, subsystem);
                (score > 0).then_some((score, subsystem.subsystem_id.clone()))
            })
            .collect();
        scored_matches
            .sort_by(|left, right| right.0.cmp(&left.0).then_with(|| left.1.cmp(&right.1)));
        let Some(best_score) = scored_matches.first().map(|(score, _)| *score) else {
            continue;
        };
        let minimum_score = revelation_subsystem_min_score(revelation.kind.as_str());
        revelation.subsystem_ids = scored_matches
            .into_iter()
            .filter(|(score, subsystem_id)| {
                (*score >= minimum_score && *score + 1 >= best_score)
                    || revelation_subsystem_forced_include(
                        revelation.kind.as_str(),
                        subsystem_id,
                        *score,
                    )
            })
            .map(|(_, subsystem_id)| subsystem_id)
            .collect();
    }
}

fn revelation_subsystem_score(
    revelation: &AndroidRevelation,
    subsystem: &crate::android::semantic::AndroidSubsystem,
) -> usize {
    let overlap_score = [
        (&subsystem.symbol_ids, 2usize),
        (&subsystem.control_surface_ids, 3usize),
        (&subsystem.transport_surface_ids, 1usize),
        (&subsystem.trust_boundary_ids, 1usize),
        (&subsystem.native_ids, 3usize),
        (&subsystem.fact_ids, 2usize),
    ]
    .into_iter()
    .map(|(members, weight)| {
        usize::from(members.iter().any(|member| {
            revelation
                .members
                .iter()
                .any(|candidate| candidate == member)
        })) * weight
    })
    .sum::<usize>();

    overlap_score
        + revelation_subsystem_kind_bonus(revelation.kind.as_str(), subsystem.kind.as_str())
}

fn revelation_subsystem_kind_bonus(revelation_kind: &str, subsystem_kind: &str) -> usize {
    match (revelation_kind, subsystem_kind) {
        ("commissioning-plane", "weave-device-security" | "matter-commissioning") => 2,
        ("fabric-authority-plane" | "key-export-risk-plane", "weave-device-security") => 2,
        ("weave-matter-bridge", "weave-device-security" | "matter-commissioning") => 2,
        ("jni-security-boundary", "weave-device-security") => 2,
        (
            "web-to-command-plane",
            "web-command-bridge" | "session-command-control" | "local-device-control",
        ) => 2,
        ("account-to-device-authority-plane", "account-device-binding") => 2,
        ("runtime-to-device-control-plane", "local-device-runtime-control") => 2,
        _ => 0,
    }
}

fn revelation_subsystem_min_score(revelation_kind: &str) -> usize {
    match revelation_kind {
        "commissioning-plane" => 4,
        "fabric-authority-plane" | "key-export-risk-plane" => 5,
        "weave-matter-bridge" => 6,
        "jni-security-boundary" => 7,
        "web-to-command-plane" => 5,
        "account-to-device-authority-plane" => 4,
        "runtime-to-device-control-plane" => 4,
        _ => 3,
    }
}

fn revelation_subsystem_forced_include(
    revelation_kind: &str,
    subsystem_id: &str,
    score: usize,
) -> bool {
    match revelation_kind {
        "weave-matter-bridge" => subsystem_id == "subsystem-matter-commissioning" && score >= 4,
        _ => false,
    }
}
