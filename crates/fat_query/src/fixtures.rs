use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;
#[cfg(feature = "test-fixtures")]
use std::path::PathBuf;

use crate::ir::{EdgeKind, EdgeRecord, NodeKind, NodeRecord};
use crate::store::InMemoryGraph;

#[cfg(feature = "test-fixtures")]
#[derive(Debug, Clone, Deserialize)]
pub struct FixtureCase {
    pub id: String,
    pub kind: String,
    pub path: String,
}

#[cfg(feature = "test-fixtures")]
#[derive(Debug, Deserialize)]
struct FixtureManifest {
    cases: Vec<FixtureCase>,
}

#[derive(Debug, Deserialize)]
struct BinaryFixture {
    nodes: Vec<FixtureNode>,
    edges: Vec<FixtureEdge>,
}

#[derive(Debug, Deserialize)]
struct FixtureNode {
    kind: String,
    label: String,
    #[serde(default)]
    attrs: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct FixtureEdge {
    kind: String,
    from: u32,
    to: u32,
}

#[cfg(feature = "test-fixtures")]
pub fn load_cases(root: impl AsRef<Path>) -> Result<Vec<FixtureCase>, String> {
    let manifest_path = root.as_ref().join("fixtures.json");
    let text = std::fs::read_to_string(&manifest_path)
        .map_err(|e| format!("failed to read {}: {}", manifest_path.display(), e))?;
    let manifest: FixtureManifest =
        serde_json::from_str(&text).map_err(|e| format!("invalid fixture manifest: {e}"))?;
    Ok(manifest
        .cases
        .into_iter()
        .map(|mut case| {
            let joined = PathBuf::from(root.as_ref()).join(&case.path);
            case.path = joined.display().to_string();
            case
        })
        .collect())
}

pub fn load_binary_graph_fixture(path: impl AsRef<Path>) -> Result<InMemoryGraph, String> {
    let fixture_path = path.as_ref().join("fixture.json");
    let text = std::fs::read_to_string(&fixture_path)
        .map_err(|e| format!("failed to read {}: {}", fixture_path.display(), e))?;
    let fixture: BinaryFixture =
        serde_json::from_str(&text).map_err(|e| format!("invalid binary fixture: {e}"))?;

    let nodes = fixture
        .nodes
        .into_iter()
        .map(|node| NodeRecord {
            id: 0,
            kind: match node.kind.as_str() {
                "Source" => NodeKind::Source,
                "Constant" => NodeKind::Constant,
                "SinkSlot" => NodeKind::SinkSlot,
                "Function" => NodeKind::Function,
                "CallSite" => NodeKind::CallSite,
                "Guard" => NodeKind::Guard,
                "Invariant" => NodeKind::Invariant,
                "InvariantSite" => NodeKind::InvariantSite,
                "PatchSite" => NodeKind::PatchSite,
                "StateChannel" => NodeKind::StateChannel,
                "RuntimeEvent" => NodeKind::RuntimeEvent,
                _ => NodeKind::Observation,
            },
            label: node.label,
            attrs: node.attrs,
            provenance: Default::default(),
        })
        .collect();

    let edges = fixture
        .edges
        .into_iter()
        .map(|edge| {
            EdgeRecord::new(
                match edge.kind.as_str() {
                    "DefUse" => EdgeKind::DefUse,
                    "ControlDependsOn" => EdgeKind::ControlDependsOn,
                    "WritesConstant" => EdgeKind::WritesConstant,
                    "GuardedBy" => EdgeKind::GuardedBy,
                    "Calls" => EdgeKind::Calls,
                    "DerivedFromPatch" => EdgeKind::DerivedFromPatch,
                    "ReadsChannel" => EdgeKind::ReadsChannel,
                    "WritesChannel" => EdgeKind::WritesChannel,
                    "SatisfiesInvariant" => EdgeKind::SatisfiesInvariant,
                    "ViolatesInvariant" => EdgeKind::ViolatesInvariant,
                    "ConfirmedByRuntime" => EdgeKind::ConfirmedByRuntime,
                    _ => EdgeKind::ContradictedByRuntime,
                },
                edge.from,
                edge.to,
            )
        })
        .collect();

    Ok(InMemoryGraph::from_records(nodes, edges))
}
