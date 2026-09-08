#[test]
fn adapter_registry_prefers_macho_structural_adapter_for_launcher_queries() {
    let registry = fat_query::adapters::registry::default_registry();
    let query = fat_query::adapters::traits::QueryRequest::new(
        fat_query::adapters::traits::QueryKind::LauncherClassification,
    );
    let target = fat_query::target_detection::DetectedTarget::new(
        fat_query::target_detection::TargetKind::MachOBinary,
        "/tmp/service-launcher",
    );

    let plan = registry.plan(&target, &query).expect("plan");

    assert_eq!(
        plan.query_kind,
        fat_query::adapters::traits::QueryKind::LauncherClassification
    );
    assert!(
        plan.adapter_ids.iter().any(|id| id == "macho-r2"),
        "expected macho-r2 in {:?}",
        plan.adapter_ids
    );
}

#[test]
fn adapter_registry_prefers_elf_flow_adapter_for_path_queries() {
    let registry = fat_query::adapters::registry::default_registry();
    let query = fat_query::adapters::traits::QueryRequest::new(
        fat_query::adapters::traits::QueryKind::Path,
    );
    let target = fat_query::target_detection::DetectedTarget::new(
        fat_query::target_detection::TargetKind::ElfBinary,
        "/tmp/httpd",
    );

    let plan = registry.plan(&target, &query).expect("plan");

    assert_eq!(
        plan.query_kind,
        fat_query::adapters::traits::QueryKind::Path
    );
    assert_eq!(
        plan.adapter_ids.first().map(String::as_str),
        Some("elf-angr")
    );
}

#[test]
fn adapter_registry_exposes_clang_source_adapter_capabilities() {
    let registry = fat_query::adapters::registry::default_registry();
    let descriptor = registry
        .descriptors()
        .iter()
        .find(|descriptor| descriptor.id == "source-clang-facts")
        .expect("source-clang-facts descriptor");

    assert!(descriptor.authoritative);
    assert!(descriptor.supported_extensions.contains(&"mm"));
    assert!(descriptor
        .modes
        .contains(&fat_query::adapters::traits::ExecutionMode::Deep));
    assert!(descriptor
        .language_families
        .contains(&fat_query::adapters::traits::SourceLanguageFamily::ObjectiveCpp));
}
