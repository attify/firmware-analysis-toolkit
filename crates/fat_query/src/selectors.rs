use crate::ir::{NodeKind, NodeRecord};
use crate::store::InMemoryGraph;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Selector {
    pub call_name: String,
    pub arg0: Option<String>,
    pub slot_name: String,
}

pub fn parse(input: &str) -> Result<Selector, String> {
    let input = input.trim();
    let (head, slot_name) = input
        .rsplit_once('.')
        .ok_or_else(|| format!("selector missing slot projection: {input}"))?;
    if !head.starts_with("call[") || !head.ends_with(']') {
        return Err(format!("unsupported selector: {input}"));
    }
    let inner = &head[5..head.len() - 1];
    let mut call_name = None;
    let mut arg0 = None;
    for part in inner.split(" and ") {
        let trimmed = part.trim();
        if let Some(rest) = trimmed.strip_prefix("name=") {
            call_name = Some(strip_quotes(rest)?);
        } else if let Some(rest) = trimmed.strip_prefix("arg0=") {
            arg0 = Some(strip_quotes(rest)?);
        }
    }
    Ok(Selector {
        call_name: call_name.ok_or_else(|| format!("selector missing name=: {input}"))?,
        arg0,
        slot_name: slot_name.to_string(),
    })
}

pub fn resolve(graph: &InMemoryGraph, selector: &Selector) -> Result<Vec<u32>, String> {
    let matches = graph
        .nodes()
        .iter()
        .filter(|node| matches_selector(node, selector))
        .map(|node| node.id)
        .collect::<Vec<_>>();
    Ok(matches)
}

fn matches_selector(node: &NodeRecord, selector: &Selector) -> bool {
    match node.kind {
        NodeKind::Source => {
            node.attr("call_name") == Some(selector.call_name.as_str())
                && node.attr("slot_name") == Some(selector.slot_name.as_str())
                && match &selector.arg0 {
                    Some(arg0) => node.attr("arg0") == Some(arg0.as_str()),
                    None => true,
                }
        }
        NodeKind::SinkSlot => {
            node.attr("sink_name") == Some(selector.call_name.as_str())
                && node.attr("slot_name") == Some(selector.slot_name.as_str())
        }
        _ => false,
    }
}

fn strip_quotes(input: &str) -> Result<String, String> {
    let trimmed = input.trim();
    if (trimmed.starts_with('"') && trimmed.ends_with('"'))
        || (trimmed.starts_with('\'') && trimmed.ends_with('\''))
    {
        Ok(trimmed[1..trimmed.len() - 1].to_string())
    } else {
        Err(format!("expected quoted string, got {input}"))
    }
}
