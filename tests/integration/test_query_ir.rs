//! Evidence-IR core: node/edge records, selectors, in-memory materialization,
//! and the SQLite snapshot store.

use fat_query::ir::{EdgeKind, EdgeRecord, NodeKind, NodeRecord};
use fat_query::store::{
    init_snapshot, load_snapshot_meta, GraphReader, GraphWriter, InMemoryGraph, SnapshotMeta,
    SCHEMA_VERSION,
};

fn fixture(relative: &str) -> String {
    format!(
        "{}/../../tests/fixtures/{relative}",
        env!("CARGO_MANIFEST_DIR")
    )
}

#[test]
fn sink_slot_node_preserves_slot_metadata() {
    let node = NodeRecord::sink_slot("popen", 0, "arg0");
    assert_eq!(node.kind, NodeKind::SinkSlot);
    assert_eq!(node.attr("sink_name"), Some("popen"));
    assert_eq!(node.attr("slot_index"), Some("0"));
}

#[test]
fn selector_matches_sink_slot_by_name_and_slot() {
    let graph = fat_query::test_graphs::single_sink_slot_graph();
    let selector = fat_query::selectors::parse(r#"call[name="popen"].arg0"#).unwrap();
    let matches = fat_query::selectors::resolve(&graph, &selector).unwrap();
    assert_eq!(matches.len(), 1);
}

#[test]
fn materialized_graph_has_forward_and_reverse_adjacency() {
    let graph = InMemoryGraph::from_records(
        vec![
            NodeRecord::source("getenv"),
            NodeRecord::sink_slot("system", 0, "arg0"),
        ],
        vec![EdgeRecord::new(EdgeKind::DefUse, 0, 1)],
    );
    assert_eq!(graph.out_edges(0).len(), 1);
    assert_eq!(graph.in_edges(1).len(), 1);
}

#[test]
fn query_snapshot_round_trips_meta() {
    let dir = tempfile::tempdir().unwrap();
    let db_path = dir.path().join("snapshot.db");
    let snapshot = SnapshotMeta::new("proj-1", "binary");
    init_snapshot(&db_path, &snapshot).unwrap();
    let loaded = load_snapshot_meta(&db_path).unwrap();
    assert_eq!(loaded.project_id, "proj-1");
    assert_eq!(loaded.target_kind, "binary");
    assert_eq!(loaded.schema_version, SCHEMA_VERSION);
}

#[test]
fn node_and_edge_records_round_trip_through_sqlite() {
    let dir = tempfile::tempdir().unwrap();
    let db = dir.path().join("snapshot.db");
    let meta = SnapshotMeta::new("proj-1", "source");
    init_snapshot(&db, &meta).unwrap();

    let mut graph = GraphWriter::open(&db).unwrap();
    let src = NodeRecord::source("getenv");
    let sink = NodeRecord::sink_slot("popen", 0, "arg0");
    let src_id = graph.insert_node(&src).unwrap();
    let sink_id = graph.insert_node(&sink).unwrap();
    graph
        .insert_edge(&EdgeRecord::new(EdgeKind::DefUse, src_id, sink_id))
        .unwrap();

    let reader = GraphReader::open(&db).unwrap();
    assert_eq!(reader.nodes().unwrap().len(), 2);
    assert_eq!(reader.edges().unwrap().len(), 1);
}

#[test]
fn query_fixtures_load_expected_cases() {
    let cases = fat_query::fixtures::load_cases(fixture("query")).unwrap();
    assert!(cases.iter().any(|c| c.id == "genie-constant-arg"));
    assert!(cases.iter().any(|c| c.id == "invariant-permission"));
    assert!(cases.iter().any(|c| c.id == "verification"));
}
