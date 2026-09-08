use std::path::Path;

use fat_core::rehosting_policy::SubstrateKind as LogicalSubstrateKind;
use fat_core::rehosting_recipe::RehostingRecipe;
use fat_core::staging::{StagingManifest, StagingMutation, StagingStrategy};

pub fn service_staging_manifest(
    project_id: &str,
    target_id: &str,
    session_id: &str,
    run_id: &str,
    source_root: &str,
    staging_root: &str,
) -> StagingManifest {
    StagingManifest::new(
        project_id,
        target_id,
        session_id,
        run_id,
        LogicalSubstrateKind::Service.as_str(),
        StagingStrategy::MutableOverlay,
        source_root,
        staging_root,
    )
    .with_generated_artifacts(vec![format!("{staging_root}/overlay")])
    .with_mutations(vec![StagingMutation::new(
        "copy",
        Some(source_root),
        staging_root,
    )
    .with_detail("materialize service-mode staging root")])
}

pub fn system_staging_manifest(
    project_id: &str,
    target_id: &str,
    session_id: &str,
    run_id: &str,
    source_root: &str,
    staging_root: &str,
) -> StagingManifest {
    let boot_root = Path::new(staging_root)
        .parent()
        .unwrap_or_else(|| Path::new(staging_root))
        .join("boot");

    StagingManifest::new(
        project_id,
        target_id,
        session_id,
        run_id,
        LogicalSubstrateKind::System.as_str(),
        StagingStrategy::CopyOnWriteImage,
        source_root,
        staging_root,
    )
    .with_generated_artifacts(vec![
        format!("{staging_root}/disk.qcow2"),
        boot_root.join("qemu-command.sh").display().to_string(),
        boot_root
            .join("surface-manifest.json")
            .display()
            .to_string(),
    ])
}

pub fn reference_staging_manifest(
    project_id: &str,
    target_id: &str,
    session_id: &str,
    run_id: &str,
    source_root: &str,
    staging_root: &str,
) -> StagingManifest {
    StagingManifest::new(
        project_id,
        target_id,
        session_id,
        run_id,
        LogicalSubstrateKind::Reference.as_str(),
        StagingStrategy::ReferenceWorkspace,
        source_root,
        staging_root,
    )
    .with_mutations(vec![StagingMutation::new(
        "mount",
        Some(source_root),
        staging_root,
    )
    .with_detail("prepare reference workspace")])
}

pub fn append_recipe_repair_materialization(
    manifest: &mut StagingManifest,
    staging_root: &str,
    recipe: &RehostingRecipe,
) {
    for node in &recipe.device_nodes {
        let staged_path = staged_guest_path(staging_root, node.path.as_str());
        push_generated_artifact(manifest, staged_path.clone());
        push_mutation(
            manifest,
            StagingMutation::new("create-node", None::<String>, staged_path)
                .with_detail(format!("materialize repaired device node {}", node.path)),
        );
    }

    for transform in &recipe.filesystem_transforms {
        if transform.destination.trim().is_empty() {
            continue;
        }
        let staged_path = staged_guest_path(staging_root, transform.destination.as_str());
        push_generated_artifact(manifest, staged_path.clone());
        push_mutation(
            manifest,
            StagingMutation::new(
                transform.transform_kind.clone(),
                Some(transform.source.clone()),
                staged_path,
            )
            .with_detail(format!(
                "materialize repaired guest {} {}",
                match transform.destination_kind {
                    fat_core::rehosting_recipe::RecipePathKind::File => "file",
                    fat_core::rehosting_recipe::RecipePathKind::Directory => "directory",
                },
                transform.destination
            )),
        );
    }
}

fn staged_guest_path(staging_root: &str, guest_path: &str) -> String {
    Path::new(staging_root)
        .join(guest_path.trim_start_matches('/'))
        .display()
        .to_string()
}

fn push_generated_artifact(manifest: &mut StagingManifest, artifact: String) {
    if !manifest
        .generated_artifacts
        .iter()
        .any(|existing| existing == &artifact)
    {
        manifest.generated_artifacts.push(artifact);
    }
}

fn push_mutation(manifest: &mut StagingManifest, mutation: StagingMutation) {
    if !manifest
        .mutations
        .iter()
        .any(|existing| existing == &mutation)
    {
        manifest.mutations.push(mutation);
    }
}
