use std::path::Path;

use crate::fixtures;
use crate::result::{ChainQueryResult, PathKind, PathResult};
use crate::selectors;

#[cfg(feature = "test-fixtures")]
pub fn run_binary_path_fixture(path: impl AsRef<Path>) -> Result<PathResult, String> {
    let graph = fixtures::load_binary_graph_fixture(path)?;
    let from = selectors::parse(r#"call[name="getenv" and arg0="QUERY_STRING"].ret"#)?;
    let to = selectors::parse(r#"call[name="popen"].arg0"#)?;
    evaluate_path(&graph, &from, &to)
}

pub fn evaluate_path(
    graph: &crate::store::InMemoryGraph,
    from: &selectors::Selector,
    to: &selectors::Selector,
) -> Result<PathResult, String> {
    let from_nodes = selectors::resolve(graph, from)?;
    let to_nodes = selectors::resolve(graph, to)?;
    if from_nodes.is_empty() || to_nodes.is_empty() {
        return Ok(PathResult {
            path_kind: PathKind::NoPath,
            connected: false,
            trace: Vec::new(),
        });
    }

    for &source in &from_nodes {
        for &sink in &to_nodes {
            if has_edge_kind_path(graph, source, sink, crate::ir::EdgeKind::DefUse) {
                let source_slot = graph.nodes()[source as usize]
                    .attr("slot_name")
                    .unwrap_or_default();
                let path_kind = if source_slot == "ret" {
                    PathKind::ReturnFlowProven
                } else if source_slot.starts_with("arg") {
                    PathKind::BufferFlowProven
                } else {
                    PathKind::ArgFlowProven
                };
                return Ok(PathResult {
                    path_kind,
                    connected: true,
                    trace: vec![
                        graph.nodes()[source as usize].label.clone(),
                        graph.nodes()[sink as usize].label.clone(),
                    ],
                });
            }
        }
    }

    for &sink in &to_nodes {
        if graph
            .in_edges(sink)
            .iter()
            .any(|edge_idx| graph.edge(*edge_idx).kind == crate::ir::EdgeKind::WritesConstant)
        {
            return Ok(PathResult {
                path_kind: PathKind::ConstantSinkArg,
                connected: false,
                trace: vec![graph.nodes()[sink as usize].label.clone()],
            });
        }
    }

    for &source in &from_nodes {
        for &sink in &to_nodes {
            if has_edge_kind_path(graph, source, sink, crate::ir::EdgeKind::ControlDependsOn) {
                return Ok(PathResult {
                    path_kind: PathKind::ControlReachable,
                    connected: false,
                    trace: vec![
                        graph.nodes()[source as usize].label.clone(),
                        graph.nodes()[sink as usize].label.clone(),
                    ],
                });
            }
            if has_edge_kind_path(graph, source, sink, crate::ir::EdgeKind::Calls) {
                return Ok(PathResult {
                    path_kind: PathKind::CallgraphOnly,
                    connected: false,
                    trace: vec![
                        graph.nodes()[source as usize].label.clone(),
                        graph.nodes()[sink as usize].label.clone(),
                    ],
                });
            }
        }
    }

    Ok(PathResult {
        path_kind: PathKind::NoPath,
        connected: false,
        trace: Vec::new(),
    })
}

fn has_edge_kind_path(
    graph: &crate::store::InMemoryGraph,
    source: u32,
    target: u32,
    edge_kind: crate::ir::EdgeKind,
) -> bool {
    let mut seen = std::collections::BTreeSet::new();
    let mut queue = std::collections::VecDeque::from([source]);
    while let Some(node) = queue.pop_front() {
        if !seen.insert(node) {
            continue;
        }
        if node == target {
            return true;
        }
        for edge_idx in graph.out_edges(node) {
            let edge = graph.edge(*edge_idx);
            if edge.kind == edge_kind {
                queue.push_back(edge.to);
            }
        }
    }
    false
}

pub fn evaluate_chain_fixture(
    path: impl AsRef<Path>,
    goal: &str,
) -> Result<ChainQueryResult, String> {
    let graph = fixtures::load_binary_graph_fixture(path)?;
    let start = graph
        .nodes()
        .iter()
        .position(|n| n.kind_name() == "Source" && n.attr("call_name") == Some("websGetVarN"))
        .ok_or("missing start source")? as u32;
    let sink = graph
        .nodes()
        .iter()
        .position(|n| n.kind_name() == "SinkSlot" && n.attr("sink_name") == Some("system"))
        .ok_or("missing sink slot")? as u32;

    let mut seen = std::collections::BTreeSet::new();
    let mut queue = std::collections::VecDeque::from([(
        start,
        vec![graph.nodes()[start as usize].label.clone()],
    )]);
    while let Some((node, steps)) = queue.pop_front() {
        if !seen.insert(node) {
            continue;
        }
        if node == sink {
            return Ok(ChainQueryResult {
                goal: goal.to_string(),
                steps,
            });
        }
        for edge_idx in graph.out_edges(node) {
            let edge = graph.edge(*edge_idx);
            if !matches!(
                edge.kind,
                crate::ir::EdgeKind::WritesChannel
                    | crate::ir::EdgeKind::ReadsChannel
                    | crate::ir::EdgeKind::DefUse
            ) {
                continue;
            }
            let mut next_steps = steps.clone();
            next_steps.push(graph.nodes()[edge.to as usize].label.clone());
            queue.push_back((edge.to, next_steps));
        }
    }

    Err("no chain found".into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ir::{EdgeKind, EdgeRecord, NodeKind, NodeRecord};
    use crate::store::InMemoryGraph;
    use std::collections::BTreeMap;

    #[test]
    fn constant_sink_arg_checks_all_matching_sink_nodes() {
        let nodes = vec![
            NodeRecord {
                id: 0,
                kind: NodeKind::Source,
                label: r#"getenv("QUERY_STRING").ret"#.into(),
                attrs: BTreeMap::from([
                    ("call_name".into(), "getenv".into()),
                    ("arg0".into(), "QUERY_STRING".into()),
                    ("slot_name".into(), "ret".into()),
                ]),
                provenance: Default::default(),
            },
            NodeRecord::sink_slot("popen", 0, "arg0"),
            NodeRecord::sink_slot("popen", 0, "arg0"),
            NodeRecord {
                id: 0,
                kind: NodeKind::Constant,
                label: "const@0xb670".into(),
                attrs: BTreeMap::new(),
                provenance: Default::default(),
            },
        ];
        let edges = vec![EdgeRecord::new(EdgeKind::WritesConstant, 3, 2)];
        let graph = InMemoryGraph::from_records(nodes, edges);
        let from = selectors::parse(r#"call[name="getenv" and arg0="QUERY_STRING"].ret"#)
            .expect("source selector");
        let to = selectors::parse(r#"call[name="popen"].arg0"#).expect("sink selector");

        let result = evaluate_path(&graph, &from, &to).expect("path evaluation");

        assert_eq!(result.path_kind, PathKind::ConstantSinkArg);
        assert!(!result.connected);
    }
}
