use fat_query::fixtures;
use fat_query::ir::{EdgeKind, EdgeRecord, NodeKind, NodeRecord};
use fat_query::store::InMemoryGraph;
use std::collections::BTreeMap;
use std::path::Path;

pub fn from_fixture(path: impl AsRef<Path>) -> Result<InMemoryGraph, String> {
    fixtures::load_binary_graph_fixture(path)
}

pub fn from_binary(path: impl AsRef<Path>) -> Result<InMemoryGraph, String> {
    let binary = path.as_ref();
    let findings = crate::proof::angr::analyze_binary_for_query(binary)
        .map_err(|e| format!("angr query analysis failed: {e}"))?;
    let binary_profile = crate::recon::r2::binary_profile(binary).ok();
    let mut constant_cache = BTreeMap::new();
    Ok(from_query_findings_with(&findings, |finding| {
        let mut observations = Vec::new();
        if let Some(observation) = constant_sink_observation(
            binary,
            binary_profile.as_ref(),
            finding,
            &mut constant_cache,
        ) {
            observations.push(observation);
        }
        observations
    }))
}

#[cfg(test)]
fn from_query_findings(findings: &[crate::proof::angr::AngrQueryFinding]) -> InMemoryGraph {
    from_query_findings_with(findings, |_| Vec::new())
}

fn from_query_findings_with<F>(
    findings: &[crate::proof::angr::AngrQueryFinding],
    mut observe: F,
) -> InMemoryGraph
where
    F: FnMut(&crate::proof::angr::AngrQueryFinding) -> Vec<SupplementalObservation>,
{
    let mut nodes = Vec::new();
    let mut edges = Vec::new();

    for finding in findings {
        let source_id = nodes.len() as u32;
        nodes.push(source_node(finding));

        let sink_id = nodes.len() as u32;
        nodes.push(sink_node(finding));

        match finding.method.as_str() {
            "confirmed-rd" => {
                edges.push(EdgeRecord::new(EdgeKind::DefUse, source_id, sink_id));
            }
            "cross-function-callgraph" | "co-occurrence" | "co-occurrence-only" => {
                edges.push(EdgeRecord::new(EdgeKind::Calls, source_id, sink_id));
            }
            _ => {
                edges.push(EdgeRecord::new(
                    EdgeKind::ControlDependsOn,
                    source_id,
                    sink_id,
                ));
            }
        }

        for observation in observe(finding) {
            match observation {
                SupplementalObservation::ConstantSinkArg { addr } => {
                    let constant_id = nodes.len() as u32;
                    nodes.push(constant_node(addr));
                    edges.push(EdgeRecord::new(
                        EdgeKind::WritesConstant,
                        constant_id,
                        sink_id,
                    ));
                }
            }
        }

        if let Some(symbolic) = &finding.symbolic_analysis {
            if symbolic
                .get("injectable")
                .and_then(|value| value.as_bool())
                .unwrap_or(false)
            {
                let observation_id = nodes.len() as u32;
                nodes.push(observation_node("symbolic injectable"));
                edges.push(EdgeRecord::new(EdgeKind::DefUse, source_id, observation_id));
                edges.push(EdgeRecord::new(EdgeKind::DefUse, observation_id, sink_id));
            }
        }
    }

    InMemoryGraph::from_records(nodes, edges)
}

enum SupplementalObservation {
    ConstantSinkArg { addr: Option<u64> },
}

fn source_node(finding: &crate::proof::angr::AngrQueryFinding) -> NodeRecord {
    let slot_name = source_slot_name(&finding.source);
    let slot_index = source_slot_index(&finding.source);
    let mut attrs = BTreeMap::new();
    attrs.insert("call_name".into(), finding.source.clone());
    attrs.insert("slot_name".into(), slot_name.into());
    attrs.insert("slot_index".into(), slot_index.to_string());
    if let Some(parameter) = &finding.parameter {
        attrs.insert("arg0".into(), parameter.clone());
    }
    if let Some(addr) = &finding.source_addr {
        attrs.insert("call_addr".into(), addr.clone());
    }
    if let Some(endpoint) = &finding.endpoint {
        attrs.insert("endpoint".into(), endpoint.clone());
    }
    NodeRecord {
        id: 0,
        kind: NodeKind::Source,
        label: match &finding.parameter {
            Some(parameter) => format!(r#"{}("{}").{}"#, finding.source, parameter, slot_name),
            None => format!("{}.{}", finding.source, slot_name),
        },
        attrs,
        provenance: Default::default(),
    }
}

fn sink_node(finding: &crate::proof::angr::AngrQueryFinding) -> NodeRecord {
    let slot_index = sink_slot_index(&finding.sink);
    let slot_name = format!("arg{slot_index}");
    let mut attrs = BTreeMap::new();
    attrs.insert("sink_name".into(), finding.sink.clone());
    attrs.insert("slot_name".into(), slot_name.clone());
    attrs.insert("slot_index".into(), slot_index.to_string());
    if let Some(addr) = &finding.sink_addr {
        attrs.insert("call_addr".into(), addr.clone());
    }
    NodeRecord {
        id: 0,
        kind: NodeKind::SinkSlot,
        label: format!("{}.{}", finding.sink, slot_name),
        attrs,
        provenance: Default::default(),
    }
}

fn observation_node(label: &str) -> NodeRecord {
    NodeRecord {
        id: 0,
        kind: NodeKind::Observation,
        label: label.into(),
        attrs: BTreeMap::new(),
        provenance: Default::default(),
    }
}

fn constant_node(addr: Option<u64>) -> NodeRecord {
    let mut attrs = BTreeMap::new();
    if let Some(addr) = addr {
        attrs.insert("addr".into(), format!("{addr:#x}"));
    }
    NodeRecord {
        id: 0,
        kind: NodeKind::Constant,
        label: match addr {
            Some(addr) => format!("const@{addr:#x}"),
            None => "const".into(),
        },
        attrs,
        provenance: Default::default(),
    }
}

fn source_slot_name(source: &str) -> &'static str {
    match source {
        "read"
        | "recv"
        | "recvfrom"
        | "HAL_UART_Receive"
        | "HAL_UART_Receive_IT"
        | "HAL_UART_Receive_DMA"
        | "HAL_SPI_Receive" => "arg1",
        "fread" | "fgets" => "arg0",
        _ => "ret",
    }
}

fn source_slot_index(source: &str) -> i32 {
    match source_slot_name(source) {
        "arg0" => 0,
        "arg1" => 1,
        _ => -1,
    }
}

fn sink_slot_index(sink: &str) -> usize {
    match sink {
        "system" | "popen" | "execl" | "execlp" | "execv" | "execve" | "execvp" => 0,
        "nvram_set"
        | "acosNvramConfig_set"
        | "acosNvramConfig_save"
        | "acosNvramConfig_setPAParam"
        | "setNvramDeviceValue" => 0,
        "sprintf" | "strcpy" | "strcat" => 0,
        _ => 0,
    }
}

fn constant_sink_observation(
    binary: &Path,
    binary_profile: Option<&crate::recon::r2::BinaryProfile>,
    finding: &crate::proof::angr::AngrQueryFinding,
    cache: &mut BTreeMap<String, bool>,
) -> Option<SupplementalObservation> {
    if finding.method != "cross-function-callgraph"
        || !supports_constant_sink_analysis(&finding.sink)
    {
        return None;
    }
    let sink_addr = parse_hex_addr(finding.sink_addr.as_deref()?)?;
    let sink_slot = sink_slot_index(&finding.sink);
    let arg_register = sink_arg_register(binary_profile?, sink_slot)?;
    let caller_addr = call_path_caller_addr(finding.call_path.as_ref());
    let cache_key = format!(
        "{}|{}|{}|{}",
        sink_addr,
        caller_addr.unwrap_or_default(),
        sink_slot,
        arg_register
    );

    if let Some(has_constant) = cache.get(&cache_key) {
        return has_constant.then_some(SupplementalObservation::ConstantSinkArg { addr: None });
    }

    let constants =
        crate::recon::r2::constant_callsite_args(binary, sink_addr, caller_addr, arg_register)
            .unwrap_or_default();
    let constant_addr = constants.first().and_then(|entry| entry.constant_addr);
    cache.insert(cache_key, constant_addr.is_some());
    constant_addr.map(|addr| SupplementalObservation::ConstantSinkArg { addr: Some(addr) })
}

fn supports_constant_sink_analysis(sink: &str) -> bool {
    matches!(
        sink,
        "system" | "popen" | "execl" | "execlp" | "execv" | "execve" | "execvp"
    )
}

fn parse_hex_addr(value: &str) -> Option<u64> {
    value
        .strip_prefix("0x")
        .or(Some(value))
        .and_then(|trimmed| u64::from_str_radix(trimmed, 16).ok())
}

fn call_path_caller_addr(call_path: Option<&Vec<String>>) -> Option<u64> {
    let caller = call_path?.iter().rev().nth(1)?;
    let (_, addr) = caller.rsplit_once('@')?;
    parse_hex_addr(addr)
}

fn sink_arg_register(
    profile: &crate::recon::r2::BinaryProfile,
    slot: usize,
) -> Option<&'static str> {
    match (profile.arch.as_str(), profile.bits, slot) {
        ("arm", _, 0) => Some("r0"),
        ("arm", _, 1) => Some("r1"),
        ("arm", _, 2) => Some("r2"),
        ("arm", _, 3) => Some("r3"),
        ("mips", _, 0) => Some("a0"),
        ("mips", _, 1) => Some("a1"),
        ("mips", _, 2) => Some("a2"),
        ("mips", _, 3) => Some("a3"),
        ("aarch64", _, 0) => Some("x0"),
        ("aarch64", _, 1) => Some("x1"),
        ("aarch64", _, 2) => Some("x2"),
        ("aarch64", _, 3) => Some("x3"),
        ("x86", 64, 0) => Some("rdi"),
        ("x86", 64, 1) => Some("rsi"),
        ("x86", 64, 2) => Some("rdx"),
        ("x86", 64, 3) => Some("rcx"),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::proof::angr::AngrQueryFinding;

    #[test]
    fn parameterized_getenv_maps_to_query_source_selector() {
        let graph = from_query_findings(&[AngrQueryFinding {
            function: "main".into(),
            source: "getenv".into(),
            source_addr: Some("0x1000".into()),
            source_class: "primary".into(),
            sink: "popen".into(),
            sink_addr: Some("0x2000".into()),
            method: "cross-function-callgraph".into(),
            call_path: Some(vec!["main@0x1000".into(), "sub_aea0@0xaea0".into()]),
            parameter: Some("QUERY_STRING".into()),
            endpoint: Some("genie.cgi".into()),
            symbolic_analysis: None,
        }]);

        let source = graph
            .nodes()
            .iter()
            .find(|node| node.kind == NodeKind::Source)
            .expect("source node");
        assert_eq!(source.attr("call_name"), Some("getenv"));
        assert_eq!(source.attr("arg0"), Some("QUERY_STRING"));
        assert_eq!(source.attr("slot_name"), Some("ret"));
    }

    #[test]
    fn cross_function_callgraph_yields_live_callgraph_only_path() {
        let graph = from_query_findings(&[AngrQueryFinding {
            function: "main".into(),
            source: "getenv".into(),
            source_addr: Some("0x1000".into()),
            source_class: "primary".into(),
            sink: "popen".into(),
            sink_addr: Some("0x2000".into()),
            method: "cross-function-callgraph".into(),
            call_path: Some(vec!["main@0x1000".into(), "sub_aea0@0xaea0".into()]),
            parameter: Some("QUERY_STRING".into()),
            endpoint: None,
            symbolic_analysis: None,
        }]);

        let from =
            fat_query::selectors::parse(r#"call[name="getenv" and arg0="QUERY_STRING"].ret"#)
                .expect("source selector");
        let to = fat_query::selectors::parse(r#"call[name="popen"].arg0"#).expect("sink selector");
        let result = fat_query::eval::evaluate_path(&graph, &from, &to).expect("path evaluation");

        assert_eq!(result.path_kind, fat_query::result::PathKind::CallgraphOnly);
        assert!(!result.connected);
    }

    #[test]
    fn tainted_buffer_sources_map_to_buffer_slot() {
        let graph = from_query_findings(&[AngrQueryFinding {
            function: "handler".into(),
            source: "read".into(),
            source_addr: Some("0x3000".into()),
            source_class: "primary".into(),
            sink: "strcpy".into(),
            sink_addr: Some("0x4000".into()),
            method: "confirmed-rd".into(),
            call_path: None,
            parameter: None,
            endpoint: None,
            symbolic_analysis: None,
        }]);

        let from =
            fat_query::selectors::parse(r#"call[name="read"].arg1"#).expect("buffer selector");
        let to = fat_query::selectors::parse(r#"call[name="strcpy"].arg0"#).expect("sink selector");
        let result = fat_query::eval::evaluate_path(&graph, &from, &to).expect("path evaluation");

        assert_eq!(
            result.path_kind,
            fat_query::result::PathKind::BufferFlowProven
        );
        assert!(result.connected);
    }

    #[test]
    fn supplemental_constant_sink_observation_classifies_constant_sink_arg() {
        let graph = from_query_findings_with(
            &[AngrQueryFinding {
                function: "main".into(),
                source: "getenv".into(),
                source_addr: Some("0x1000".into()),
                source_class: "primary".into(),
                sink: "popen".into(),
                sink_addr: Some("0x2000".into()),
                method: "cross-function-callgraph".into(),
                call_path: Some(vec!["main@0x1000".into(), "sub_aea0@0xaea0".into()]),
                parameter: Some("QUERY_STRING".into()),
                endpoint: None,
                symbolic_analysis: None,
            }],
            |_| vec![SupplementalObservation::ConstantSinkArg { addr: Some(0xb670) }],
        );

        let from =
            fat_query::selectors::parse(r#"call[name="getenv" and arg0="QUERY_STRING"].ret"#)
                .expect("source selector");
        let to = fat_query::selectors::parse(r#"call[name="popen"].arg0"#).expect("sink selector");
        let result = fat_query::eval::evaluate_path(&graph, &from, &to).expect("path evaluation");

        assert_eq!(
            result.path_kind,
            fat_query::result::PathKind::ConstantSinkArg
        );
        assert!(!result.connected);
    }

    #[test]
    fn call_path_caller_addr_extracts_penultimate_function_address() {
        assert_eq!(
            call_path_caller_addr(Some(&vec!["main@0xa118".into(), "sub_aea0@0xaea0".into()])),
            Some(0xa118)
        );
    }
}
