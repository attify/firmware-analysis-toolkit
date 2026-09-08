use fat_core::rehosting_policy::{SubstrateKind, SubstratePreference};
use fat_core::rehosting_recipe::RehostingRecipe;

#[test]
fn rehosting_recipe_ids_are_stable_for_identical_inputs() {
    let left = RehostingRecipe::new(
        "target-a",
        "model-a",
        "run-a",
        "emulate firmware",
        SubstratePreference::Auto,
        SubstrateKind::System,
    );
    let right = RehostingRecipe::new(
        "target-a",
        "model-a",
        "run-a",
        "emulate firmware",
        SubstratePreference::Auto,
        SubstrateKind::System,
    );

    assert_eq!(left.rehosting_recipe_id, right.rehosting_recipe_id);
}
