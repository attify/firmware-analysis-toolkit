#[test]
fn planner_prefers_selector_first_for_path_query() {
    let query = fat_query::parser::parse_query(
        r#"
kind: path
from: call[name="getenv"].ret
to: call[name="system"].arg0
"#,
    )
    .unwrap();
    let plan = fat_query::planner::build_plan(&query).unwrap();
    assert_eq!(plan.steps[0].kind_name(), "resolve_selectors");
}

#[test]
fn source_planner_keeps_multiple_adapters_and_deep_stages_for_objcpp() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    std::fs::write(
        root.join("TextureMtl.mm"),
        "int MakeBuffer(int x) { return x; }\n",
    )
    .expect("write source");
    std::fs::write(
        root.join("compile_flags.txt"),
        "-x\nobjective-c++\n-std=c++17\n-target\narm64-apple-darwin\n",
    )
    .expect("write compile flags");

    let plan = fat_query::planner::build_source_analysis_plan(
        root,
        fat_query::adapters::traits::QueryKind::PatchInvariant,
        fat_query::adapters::traits::ExecutionMode::Deep,
    )
    .expect("source plan");

    assert!(
        plan.adapter_ids
            .iter()
            .any(|id| id == "source-tree-sitter-c"),
        "expected lightweight scanner in {:?}",
        plan.adapter_ids
    );
    assert!(
        plan.adapter_ids.iter().any(|id| id == "source-clang-facts"),
        "expected clang facts in {:?}",
        plan.adapter_ids
    );
    assert!(plan.stages.iter().any(|stage| stage.kind == "variant_hunt"));
    assert!(plan.budgets.max_neighborhood_breadth >= 5);
    assert_eq!(plan.mode.as_str(), "deep");
}

#[test]
fn source_planner_makes_triage_materially_cheaper_than_deep() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    std::fs::write(root.join("sample.cpp"), "int f() { return 0; }\n").expect("write source");

    let triage = fat_query::planner::build_source_analysis_plan(
        root,
        fat_query::adapters::traits::QueryKind::Invariant,
        fat_query::adapters::traits::ExecutionMode::Triage,
    )
    .expect("triage plan");
    let deep = fat_query::planner::build_source_analysis_plan(
        root,
        fat_query::adapters::traits::QueryKind::Invariant,
        fat_query::adapters::traits::ExecutionMode::Deep,
    )
    .expect("deep plan");

    assert!(triage.budgets.per_tu_timeout_ms < deep.budgets.per_tu_timeout_ms);
    assert!(triage.budgets.max_neighborhood_breadth < deep.budgets.max_neighborhood_breadth);
    assert!(triage.stages.len() < deep.stages.len());
}

#[test]
fn source_planner_resolves_codeql_database_to_analysis_root() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source_root = dir.path().join("kernel-src");
    let db_root = dir.path().join("binder-db");
    std::fs::create_dir_all(source_root.join("drivers/android")).expect("source root");
    std::fs::create_dir_all(&db_root).expect("db root");
    std::fs::write(
        source_root.join("drivers/android/binder_alloc.c"),
        "int binder_alloc() { return 0; }\n",
    )
    .expect("write source");
    std::fs::write(
        db_root.join("codeql-database.yml"),
        format!(
            "---\nsourceLocationPrefix: {}\nprimaryLanguage: cpp\nfinalised: true\n",
            source_root.display()
        ),
    )
    .expect("metadata");

    let plan = fat_query::planner::build_source_analysis_plan(
        &db_root,
        fat_query::adapters::traits::QueryKind::Invariant,
        fat_query::adapters::traits::ExecutionMode::Triage,
    )
    .expect("codeql plan");

    assert_eq!(
        plan.target_kind,
        fat_query::target_detection::TargetKind::CodeQlDatabase
    );
    assert_eq!(plan.analysis_root, source_root);
    assert_eq!(plan.codeql_db_root, Some(db_root));
}
