use crate::android::semantic::AndroidSemanticBundle;
use serde::{Deserialize, Serialize};
use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet, BinaryHeap};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidChainStep {
    pub node_id: String,
    pub kind: String,
    pub label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AndroidChainReport {
    pub status: String,
    pub entry: String,
    pub sink: String,
    pub path_found: bool,
    #[serde(default)]
    pub matched_entry_nodes: Vec<String>,
    #[serde(default)]
    pub matched_sink_nodes: Vec<String>,
    #[serde(default)]
    pub steps: Vec<AndroidChainStep>,
    #[serde(default)]
    pub warnings: Vec<String>,
    pub message: String,
}

#[derive(Debug, Clone)]
struct ChainNode {
    kind: String,
    label: String,
    searchable: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum EdgeStrength {
    Weak,
    Medium,
    Strong,
}

#[derive(Debug, Clone)]
struct ChainEdge {
    to: String,
    cost: u32,
    strength: EdgeStrength,
}

pub fn build_android_chain_report(
    bundle: &AndroidSemanticBundle,
    entry: &str,
    sink: &str,
) -> AndroidChainReport {
    let graph = build_chain_graph(bundle);
    let normalized_entry = normalize_query(entry);
    let normalized_sink = normalize_query(sink);

    let matched_entry_nodes: Vec<String> = graph
        .nodes
        .iter()
        .filter(|(_, node)| matches_query(node, &normalized_entry))
        .map(|(id, _)| id.clone())
        .collect();
    let matched_sink_nodes: Vec<String> = graph
        .nodes
        .iter()
        .filter(|(_, node)| matches_query(node, &normalized_sink))
        .map(|(id, _)| id.clone())
        .collect();

    if matched_entry_nodes.is_empty() || matched_sink_nodes.is_empty() {
        let mut warnings = Vec::new();
        if matched_entry_nodes.is_empty() {
            warnings.push(format!("no nodes matched entry query {entry}"));
        }
        if matched_sink_nodes.is_empty() {
            warnings.push(format!("no nodes matched sink query {sink}"));
        }
        return AndroidChainReport {
            status: "no-match".into(),
            entry: entry.into(),
            sink: sink.into(),
            path_found: false,
            matched_entry_nodes,
            matched_sink_nodes,
            steps: Vec::new(),
            warnings,
            message: "No chain query matches were found in the semantic bundle.".into(),
        };
    }

    if let Some(path) = weighted_path(&graph, &matched_entry_nodes, &matched_sink_nodes) {
        let steps = path
            .iter()
            .filter_map(|id| {
                graph.nodes.get(id).map(|node| AndroidChainStep {
                    node_id: id.clone(),
                    kind: node.kind.clone(),
                    label: node.label.clone(),
                })
            })
            .collect();
        AndroidChainReport {
            status: "ok".into(),
            entry: entry.into(),
            sink: sink.into(),
            path_found: true,
            matched_entry_nodes,
            matched_sink_nodes,
            steps,
            warnings: Vec::new(),
            message: "Chain reconstructed from semantic bundle.".into(),
        }
    } else {
        AndroidChainReport {
            status: "no-path".into(),
            entry: entry.into(),
            sink: sink.into(),
            path_found: false,
            matched_entry_nodes,
            matched_sink_nodes,
            steps: Vec::new(),
            warnings: Vec::new(),
            message: "Entry and sink were matched, but no semantic path connected them.".into(),
        }
    }
}

struct ChainGraph {
    nodes: BTreeMap<String, ChainNode>,
    edges: BTreeMap<String, BTreeMap<String, ChainEdge>>,
}

fn build_chain_graph(bundle: &AndroidSemanticBundle) -> ChainGraph {
    let mut nodes = BTreeMap::new();
    let mut edges = BTreeMap::new();
    let mut member_lookup = BTreeMap::new();

    for fact in &bundle.facts {
        let node_id = format!("fact:{}", fact.fact_id);
        let label = fact.subject.clone();
        nodes.insert(
            node_id.clone(),
            ChainNode {
                kind: "fact".into(),
                label: label.clone(),
                searchable: vec![
                    fact.kind.clone(),
                    fact.subject.clone(),
                    fact.fact_id.clone(),
                ],
            },
        );
        member_lookup.insert(fact.fact_id.clone(), node_id);
    }

    for symbol in &bundle.symbol_identities {
        let node_id = format!("symbol:{}", symbol.symbol_id);
        nodes.insert(
            node_id.clone(),
            ChainNode {
                kind: "symbol".into(),
                label: symbol.qualified_name.clone(),
                searchable: vec![
                    symbol.kind.clone(),
                    symbol.qualified_name.clone(),
                    symbol.symbol_id.clone(),
                ],
            },
        );
        member_lookup.insert(symbol.symbol_id.clone(), node_id);
    }

    for surface in &bundle.control_surfaces {
        let node_id = format!("control:{}", surface.surface_id);
        let label = surface
            .trigger
            .clone()
            .map(|trigger| format!("{} [{}]", surface.kind, trigger))
            .unwrap_or_else(|| surface.kind.clone());
        let mut searchable = vec![surface.kind.clone(), surface.surface_id.clone()];
        if let Some(trigger) = &surface.trigger {
            searchable.push(trigger.clone());
        }
        searchable.extend(surface.notes.clone());
        nodes.insert(
            node_id.clone(),
            ChainNode {
                kind: "control_surface".into(),
                label,
                searchable,
            },
        );
        member_lookup.insert(surface.surface_id.clone(), node_id.clone());
        if let Some(symbol_id) = &surface.entry_symbol {
            if let Some(symbol_node) = member_lookup.get(symbol_id) {
                add_edge(&mut edges, &node_id, symbol_node, 1, EdgeStrength::Strong);
            }
        }
    }

    for subsystem in &bundle.subsystems {
        let node_id = format!("subsystem:{}", subsystem.subsystem_id);
        nodes.insert(
            node_id.clone(),
            ChainNode {
                kind: "subsystem".into(),
                label: subsystem.kind.clone(),
                searchable: vec![
                    subsystem.kind.clone(),
                    subsystem.subsystem_id.clone(),
                    subsystem.package_prefixes.join(" "),
                ],
            },
        );
        member_lookup.insert(subsystem.subsystem_id.clone(), node_id.clone());
        let (cost, strength) = subsystem_edge_weight(subsystem.kind.as_str());
        for member in subsystem
            .symbol_ids
            .iter()
            .chain(subsystem.control_surface_ids.iter())
            .chain(subsystem.transport_surface_ids.iter())
            .chain(subsystem.trust_boundary_ids.iter())
            .chain(subsystem.native_ids.iter())
            .chain(subsystem.fact_ids.iter())
        {
            if let Some(member_node) = member_lookup.get(member) {
                add_edge(&mut edges, &node_id, member_node, cost, strength);
            }
        }
    }

    for revelation in &bundle.revelations {
        let node_id = format!("revelation:{}", revelation.revelation_id);
        nodes.insert(
            node_id.clone(),
            ChainNode {
                kind: "revelation".into(),
                label: revelation.kind.clone(),
                searchable: vec![revelation.kind.clone(), revelation.revelation_id.clone()],
            },
        );
        for subsystem_id in &revelation.subsystem_ids {
            if let Some(subsystem_node) = member_lookup.get(subsystem_id) {
                add_edge(&mut edges, &node_id, subsystem_node, 8, EdgeStrength::Weak);
            }
        }
        for member in &revelation.members {
            if let Some(member_node) = member_lookup.get(member) {
                add_edge(&mut edges, &node_id, member_node, 8, EdgeStrength::Weak);
            }
        }
    }

    for correlation in &bundle.correlations {
        let node_id = format!("correlation:{}", correlation.correlation_id);
        nodes.insert(
            node_id.clone(),
            ChainNode {
                kind: "correlation".into(),
                label: correlation.kind.clone(),
                searchable: vec![correlation.kind.clone(), correlation.correlation_id.clone()],
            },
        );
        let (cost, strength) = correlation_edge_weight(correlation.kind.as_str());
        for member in &correlation.members {
            if let Some(member_node) = member_lookup.get(member) {
                add_edge(&mut edges, &node_id, member_node, cost, strength);
            }
        }
    }

    connect_command_facts(bundle, &member_lookup, &mut edges);
    connect_binding_controls(bundle, &member_lookup, &mut edges);

    ChainGraph { nodes, edges }
}

fn connect_command_facts(
    bundle: &AndroidSemanticBundle,
    member_lookup: &BTreeMap<String, String>,
    edges: &mut BTreeMap<String, BTreeMap<String, ChainEdge>>,
) {
    let command_controls: Vec<String> = bundle
        .control_surfaces
        .iter()
        .filter(|surface| {
            matches!(
                surface.kind.as_str(),
                "remote-command-dispatch" | "web-command-bridge"
            )
        })
        .filter_map(|surface| member_lookup.get(&surface.surface_id).cloned())
        .collect();

    if command_controls.is_empty() {
        return;
    }

    for fact in &bundle.facts {
        if matches!(
            fact.kind.as_str(),
            "role.command-catalog-entry" | "role.command-envelope-field"
        ) {
            if let Some(fact_node) = member_lookup.get(&fact.fact_id) {
                for control in &command_controls {
                    add_edge(edges, fact_node, control, 1, EdgeStrength::Strong);
                }
            }
        }
    }
}

fn connect_binding_controls(
    bundle: &AndroidSemanticBundle,
    member_lookup: &BTreeMap<String, String>,
    edges: &mut BTreeMap<String, BTreeMap<String, ChainEdge>>,
) {
    let binding_controls: Vec<String> = bundle
        .control_surfaces
        .iter()
        .filter(|surface| surface.kind == "account-device-bind-flow")
        .filter_map(|surface| member_lookup.get(&surface.surface_id).cloned())
        .collect();
    if binding_controls.is_empty() {
        return;
    }

    for surface in &bundle.control_surfaces {
        if !matches!(
            surface.kind.as_str(),
            "http-api-endpoint" | "signaling-endpoint"
        ) {
            continue;
        }
        let trigger = surface
            .trigger
            .clone()
            .unwrap_or_default()
            .to_ascii_lowercase();
        if !(trigger.contains("bind") || trigger.contains("token") || trigger.contains("oauth")) {
            continue;
        }
        if let Some(surface_node) = member_lookup.get(&surface.surface_id) {
            for binding in &binding_controls {
                add_edge(edges, surface_node, binding, 1, EdgeStrength::Strong);
            }
        }
    }
}

fn add_edge(
    edges: &mut BTreeMap<String, BTreeMap<String, ChainEdge>>,
    left: &str,
    right: &str,
    cost: u32,
    strength: EdgeStrength,
) {
    if left == right {
        return;
    }
    insert_edge(edges, left, right, cost, strength);
    insert_edge(edges, right, left, cost, strength);
}

fn insert_edge(
    edges: &mut BTreeMap<String, BTreeMap<String, ChainEdge>>,
    from: &str,
    to: &str,
    cost: u32,
    strength: EdgeStrength,
) {
    let entry = edges.entry(from.to_string()).or_default();
    match entry.get(to) {
        Some(existing)
            if existing.cost < cost || (existing.cost == cost && existing.strength >= strength) => {
        }
        _ => {
            entry.insert(
                to.to_string(),
                ChainEdge {
                    to: to.to_string(),
                    cost,
                    strength,
                },
            );
        }
    }
}

fn weighted_path(graph: &ChainGraph, sources: &[String], sinks: &[String]) -> Option<Vec<String>> {
    let sink_set: BTreeSet<String> = sinks.iter().cloned().collect();
    let mut heap = BinaryHeap::new();
    let mut distance = BTreeMap::<String, u32>::new();
    let mut parent = BTreeMap::<String, String>::new();

    for source in sources {
        distance.insert(source.clone(), 0);
        heap.push(QueueState {
            cost: 0,
            node_id: source.clone(),
        });
    }

    while let Some(state) = heap.pop() {
        let current_best = distance.get(&state.node_id).copied().unwrap_or(u32::MAX);
        if state.cost > current_best {
            continue;
        }
        if sink_set.contains(&state.node_id) {
            let path = reconstruct_path(state.node_id.clone(), &parent);
            if path_is_admissible(graph, &path) {
                return Some(path);
            }
        }
        if let Some(neighbors) = graph.edges.get(&state.node_id) {
            for edge in neighbors.values() {
                let next_cost = state.cost.saturating_add(edge.cost);
                let known = distance.get(&edge.to).copied().unwrap_or(u32::MAX);
                if next_cost < known {
                    distance.insert(edge.to.clone(), next_cost);
                    parent.insert(edge.to.clone(), state.node_id.clone());
                    heap.push(QueueState {
                        cost: next_cost,
                        node_id: edge.to.clone(),
                    });
                }
            }
        }
    }
    None
}

fn reconstruct_path(mut current: String, parent: &BTreeMap<String, String>) -> Vec<String> {
    let mut path = vec![current.clone()];
    while let Some(prev) = parent.get(&current) {
        path.push(prev.clone());
        current = prev.clone();
    }
    path.reverse();
    path
}

fn matches_query(node: &ChainNode, normalized_query: &str) -> bool {
    if normalized_query.is_empty() {
        return false;
    }
    node.searchable
        .iter()
        .chain(std::iter::once(&node.label))
        .map(|value| normalize_query(value))
        .any(|value| value.contains(normalized_query))
}

fn normalize_query(value: &str) -> String {
    value
        .chars()
        .filter(|ch| ch.is_ascii_alphanumeric())
        .flat_map(|ch| ch.to_lowercase())
        .collect()
}

fn subsystem_edge_weight(kind: &str) -> (u32, EdgeStrength) {
    match kind {
        "local-device-runtime-control" | "runtime-account-auth" => (2, EdgeStrength::Strong),
        "runtime-firmware-update"
        | "runtime-embedded-web-content"
        | "web-command-bridge"
        | "session-command-control"
        | "local-device-control"
        | "account-device-binding" => (3, EdgeStrength::Medium),
        "flutter-runtime" => (9, EdgeStrength::Weak),
        _ => (4, EdgeStrength::Medium),
    }
}

fn correlation_edge_weight(kind: &str) -> (u32, EdgeStrength) {
    match kind {
        "runtime-role-cluster" => (1, EdgeStrength::Strong),
        _ => (3, EdgeStrength::Medium),
    }
}

fn path_is_admissible(graph: &ChainGraph, path: &[String]) -> bool {
    let mut has_strong_edge = false;
    let mut has_runtime_role_cluster = false;
    let mut has_narrow_subsystem = false;
    let mut has_chainable_control = false;
    let mut has_informational_endpoint = false;
    let mut has_runtime_revelation = false;

    for node_id in path {
        let Some(node) = graph.nodes.get(node_id) else {
            continue;
        };
        match node.kind.as_str() {
            "revelation" => {
                has_runtime_revelation = node.label == "runtime-to-device-control-plane";
            }
            "correlation" if node.label == "runtime-role-cluster" => {
                has_runtime_role_cluster = true;
            }
            "subsystem" if is_narrow_chain_subsystem(&node.label) => {
                has_narrow_subsystem = true;
            }
            "control_surface" => {
                if node.label.starts_with("http-info-endpoint") {
                    has_informational_endpoint = true;
                }
                if node.label.starts_with("http-api-endpoint")
                    || node.label.starts_with("local-device-control-surface")
                {
                    has_chainable_control = true;
                }
            }
            "trust_boundary" => {
                has_chainable_control = true;
            }
            _ => {}
        }
    }

    for pair in path.windows(2) {
        let [left, right] = pair else {
            continue;
        };
        if graph
            .edges
            .get(left)
            .and_then(|neighbors| neighbors.get(right))
            .is_some_and(|edge| edge.strength == EdgeStrength::Strong)
        {
            has_strong_edge = true;
            break;
        }
    }

    if has_informational_endpoint && !(has_strong_edge || has_runtime_role_cluster) {
        return false;
    }

    if has_runtime_revelation && !(has_runtime_role_cluster || has_chainable_control) {
        return false;
    }

    has_strong_edge || has_runtime_role_cluster || (has_narrow_subsystem && has_chainable_control)
}

fn is_narrow_chain_subsystem(label: &str) -> bool {
    matches!(
        label,
        "local-device-runtime-control"
            | "runtime-account-auth"
            | "runtime-firmware-update"
            | "runtime-embedded-web-content"
            | "local-device-control"
            | "account-device-binding"
            | "web-command-bridge"
            | "session-command-control"
    )
}

#[derive(Debug, Clone, Eq, PartialEq)]
struct QueueState {
    cost: u32,
    node_id: String,
}

impl Ord for QueueState {
    fn cmp(&self, other: &Self) -> Ordering {
        other
            .cost
            .cmp(&self.cost)
            .then_with(|| other.node_id.cmp(&self.node_id))
    }
}

impl PartialOrd for QueueState {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
