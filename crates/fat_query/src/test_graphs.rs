use crate::ir::{EdgeKind, EdgeRecord, NodeRecord};
use crate::store::InMemoryGraph;

pub fn single_sink_slot_graph() -> InMemoryGraph {
    InMemoryGraph::from_records(
        vec![
            NodeRecord::source("getenv"),
            NodeRecord::sink_slot("popen", 0, "arg0"),
        ],
        vec![EdgeRecord::new(EdgeKind::DefUse, 0, 1)],
    )
}
