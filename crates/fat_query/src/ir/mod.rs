use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub type NodeId = u32;
pub type EdgeId = u32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum NodeKind {
    Source,
    Constant,
    SinkSlot,
    Function,
    CallSite,
    Guard,
    Invariant,
    InvariantSite,
    PatchSite,
    StateChannel,
    RuntimeEvent,
    Observation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum EdgeKind {
    DefUse,
    ControlDependsOn,
    WritesConstant,
    GuardedBy,
    Calls,
    DerivedFromPatch,
    ReadsChannel,
    WritesChannel,
    SatisfiesInvariant,
    ViolatesInvariant,
    ConfirmedByRuntime,
    ContradictedByRuntime,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Provenance {
    pub source: String,
    pub confidence_millis: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRecord {
    pub id: NodeId,
    pub kind: NodeKind,
    pub label: String,
    pub attrs: BTreeMap<String, String>,
    pub provenance: Provenance,
}

impl NodeRecord {
    pub fn source(label: impl Into<String>) -> Self {
        Self {
            id: 0,
            kind: NodeKind::Source,
            label: label.into(),
            attrs: BTreeMap::new(),
            provenance: Provenance::default(),
        }
    }

    pub fn sink_slot(sink_name: &str, slot_index: usize, slot_name: &str) -> Self {
        let mut attrs = BTreeMap::new();
        attrs.insert("sink_name".into(), sink_name.into());
        attrs.insert("slot_index".into(), slot_index.to_string());
        attrs.insert("slot_name".into(), slot_name.into());
        Self {
            id: 0,
            kind: NodeKind::SinkSlot,
            label: format!("{sink_name}.{slot_name}"),
            attrs,
            provenance: Provenance::default(),
        }
    }

    pub fn attr(&self, key: &str) -> Option<&str> {
        self.attrs.get(key).map(String::as_str)
    }

    pub fn kind_name(&self) -> &'static str {
        match self.kind {
            NodeKind::Source => "Source",
            NodeKind::Constant => "Constant",
            NodeKind::SinkSlot => "SinkSlot",
            NodeKind::Function => "Function",
            NodeKind::CallSite => "CallSite",
            NodeKind::Guard => "Guard",
            NodeKind::Invariant => "Invariant",
            NodeKind::InvariantSite => "InvariantSite",
            NodeKind::PatchSite => "PatchSite",
            NodeKind::StateChannel => "StateChannel",
            NodeKind::RuntimeEvent => "RuntimeEvent",
            NodeKind::Observation => "Observation",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EdgeRecord {
    pub id: EdgeId,
    pub kind: EdgeKind,
    pub from: NodeId,
    pub to: NodeId,
    pub attrs: BTreeMap<String, String>,
    pub provenance: Provenance,
}

impl EdgeRecord {
    pub fn new(kind: EdgeKind, from: NodeId, to: NodeId) -> Self {
        Self {
            id: 0,
            kind,
            from,
            to,
            attrs: BTreeMap::new(),
            provenance: Provenance::default(),
        }
    }

    pub fn kind_name(&self) -> &'static str {
        match self.kind {
            EdgeKind::DefUse => "DefUse",
            EdgeKind::ControlDependsOn => "ControlDependsOn",
            EdgeKind::WritesConstant => "WritesConstant",
            EdgeKind::GuardedBy => "GuardedBy",
            EdgeKind::Calls => "Calls",
            EdgeKind::DerivedFromPatch => "DerivedFromPatch",
            EdgeKind::ReadsChannel => "ReadsChannel",
            EdgeKind::WritesChannel => "WritesChannel",
            EdgeKind::SatisfiesInvariant => "SatisfiesInvariant",
            EdgeKind::ViolatesInvariant => "ViolatesInvariant",
            EdgeKind::ConfirmedByRuntime => "ConfirmedByRuntime",
            EdgeKind::ContradictedByRuntime => "ContradictedByRuntime",
        }
    }
}
