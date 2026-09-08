use fat_query::adapters::registry::default_registry;
use fat_query::adapters::traits::QueryKind;
use fat_query::target_detection::detect_path;
use std::path::Path;

pub(crate) fn adapter_plan_note(file: &Path, query_kind: QueryKind) -> String {
    let target = match detect_path(file) {
        Ok(target) => target,
        Err(err) => {
            return format!("target detection failed for {}: {err}", file.display());
        }
    };

    let registry = default_registry();
    let request = fat_query::adapters::traits::QueryRequest::new(query_kind);
    match registry.plan(&target, &request) {
        Ok(plan) => format!(
            "adapter plan for {:?}: {}",
            plan.query_kind,
            plan.adapter_ids.join(" -> ")
        ),
        Err(err) => format!("no dedicated adapter plan for {:?}: {}", target.kind, err),
    }
}
