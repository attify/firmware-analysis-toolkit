//! Evidence-IR adapters: what each adapter contributes to the shared graph
//! when run against its checked-in fixture.

fn fixture(relative: &str) -> String {
    format!(
        "{}/../../tests/fixtures/{relative}",
        env!("CARGO_MANIFEST_DIR")
    )
}

const INVARIANT_PERMISSION: &str = "query/source/invariant-permission";

#[test]
fn source_adapter_indexes_functions_and_calls() {
    let graph =
        fat_query::adapters::source::index_repo_fixture(fixture(INVARIANT_PERMISSION)).unwrap();
    assert!(graph.nodes().iter().any(|n| n.kind_name() == "Function"));
    assert!(graph.nodes().iter().any(|n| n.kind_name() == "CallSite"));
}

#[test]
fn source_adapter_extracts_permission_guard_relations() {
    let graph =
        fat_query::adapters::source::index_repo_fixture(fixture(INVARIANT_PERMISSION)).unwrap();
    assert!(graph.edges().iter().any(|e| e.kind_name() == "GuardedBy"));
}

#[test]
fn patch_adapter_marks_reference_and_neighbor_sites() {
    let graph =
        fat_query::adapters::invariant::from_patch_fixture(fixture(INVARIANT_PERMISSION)).unwrap();
    assert!(graph
        .edges()
        .iter()
        .any(|e| e.kind_name() == "DerivedFromPatch"));
}

#[test]
fn runtime_adapter_can_mark_static_result_confirmed() {
    let result =
        fat_query::adapters::runtime::confirm_fixture(fixture("query/runtime/verification"))
            .unwrap();
    assert_eq!(result.verdict_name(), "Confirmed");
}

#[test]
fn binary_adapter_emits_sink_slot_nodes() {
    let graph =
        fat_taint::query::binary_adapter::from_fixture(fixture("query/binary/genie-constant-arg"))
            .unwrap();
    assert!(graph.nodes().iter().any(|n| n.kind_name() == "SinkSlot"));
    assert!(graph
        .nodes()
        .iter()
        .any(|n| n.attr("sink_name") == Some("popen")));
}

#[test]
fn binary_adapter_emits_nvram_channel_edges() {
    let graph =
        fat_taint::query::binary_adapter::from_fixture(fixture("query/binary/httpd-cross-channel"))
            .unwrap();
    assert!(graph
        .edges()
        .iter()
        .any(|e| e.kind_name() == "WritesChannel"));
    assert!(graph
        .edges()
        .iter()
        .any(|e| e.kind_name() == "ReadsChannel"));
}

#[test]
fn genie_constant_command_is_not_arg_flow_proven() {
    let result =
        fat_query::eval::run_binary_path_fixture(fixture("query/binary/genie-constant-arg"))
            .unwrap();
    assert_eq!(
        result.path_kind,
        fat_query::result::PathKind::ConstantSinkArg
    );
}
