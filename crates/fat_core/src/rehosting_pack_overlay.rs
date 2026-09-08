//! Translate a matched [`RehostingPack`](crate::rehosting_pack::RehostingPack)
//! into a set of overrides that can be applied onto a
//! [`RehostingRecipe`](crate::rehosting_recipe::RehostingRecipe). Pure data
//! transformation — no I/O or emulation deps — so it is fully unit-testable
//! without a live host.

use crate::rehosting_pack::{PackPartitionRole, RehostingPack};
use crate::rehosting_recipe::{
    RecipeFilesystemTransform, RecipeNetworkConfig, RecipePartitionMaterialization,
    RecipeValidator, RehostingCapabilityReport, RehostingRecipe,
};

/// Overrides derived from a rehosting pack, ready to apply to a recipe.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PackOverlay {
    pub pack_id: String,
    pub pack_version: String,
    pub requested_substrate: Option<String>,
    pub partition_roles: Vec<PackPartitionRole>,
    pub qemu_machine: Option<String>,
    pub network_mode: Option<String>,
    pub network_interface: Option<String>,
    pub network_fallback_ip: Option<String>,
    pub extra_validators: Vec<RecipeValidator>,
    pub materialize_transforms: Vec<RecipeFilesystemTransform>,
    pub command_shims: Vec<String>,
    pub module_skip_patterns: Vec<String>,
    /// Free-form repair flags, e.g. `repair:skip-command:<x>`.
    pub skip_flags: Vec<String>,
    pub caveats: Vec<String>,
    /// Human-readable summary of what the overlay changes (for surfacing).
    pub applied: Vec<String>,
}

impl PackOverlay {
    /// Derive an overlay from a pack. Sections the pack does not declare produce
    /// no overrides.
    pub fn from_pack(pack: &RehostingPack) -> Self {
        let mut overlay = PackOverlay {
            pack_id: pack.id.clone(),
            pack_version: pack.version.clone(),
            ..PackOverlay::default()
        };

        if let Some(runtime) = &pack.runtime {
            if let Some(substrate) = &runtime.substrate {
                overlay.requested_substrate = Some(substrate.clone());
                overlay.applied.push(format!("substrate = {substrate}"));
            }
            if let Some(machine) = &runtime.qemu_machine {
                overlay.qemu_machine = Some(machine.clone());
                overlay.applied.push(format!("qemu machine = {machine}"));
            }
            if let Some(network) = &runtime.network {
                overlay.network_mode = network.mode.clone();
                overlay.network_interface = network.interface.clone();
                overlay.network_fallback_ip = network.fallback_ip.clone();
                if let Some(mode) = &network.mode {
                    overlay.applied.push(format!("network mode = {mode}"));
                }
            }
        }

        if let Some(partitions) = &pack.partitions {
            overlay.partition_roles = partitions.roles.clone();
        }

        for validator in &pack.validators {
            let mut recipe_validator =
                RecipeValidator::new(validator.goal.clone(), validator.kind.clone());
            recipe_validator.pattern = validator.pattern.clone();
            recipe_validator.name = validator.name.clone();
            recipe_validator.path = validator.path.clone();
            recipe_validator.port = validator.port;
            overlay.extra_validators.push(recipe_validator);
        }
        if !pack.validators.is_empty() {
            overlay
                .applied
                .push(format!("{} pack validator(s)", pack.validators.len()));
        }

        if let Some(repairs) = &pack.repairs {
            if let Some(init) = &repairs.init {
                for path in &init.materialize_paths {
                    overlay
                        .materialize_transforms
                        .push(RecipeFilesystemTransform::directory(
                            "materialize",
                            path.clone(),
                        ));
                }
                for command in &init.skip_commands {
                    overlay.command_shims.push(command.clone());
                    overlay
                        .skip_flags
                        .push(format!("repair:skip-command:{command}"));
                }
                for pattern in &init.skip_module_loads_matching {
                    overlay.module_skip_patterns.push(pattern.clone());
                    overlay
                        .skip_flags
                        .push(format!("repair:skip-module:{pattern}"));
                }
                if !init.materialize_paths.is_empty() {
                    overlay.applied.push(format!(
                        "{} materialize path(s)",
                        init.materialize_paths.len()
                    ));
                }
                if !overlay.skip_flags.is_empty() {
                    overlay
                        .applied
                        .push(format!("{} init repair(s)", overlay.skip_flags.len()));
                }
            }
        }

        overlay.caveats = pack.caveats.clone();

        overlay
    }

    /// Apply the overlay to a recipe in place. Idempotent: re-applying (e.g.
    /// after the emulator rebuilds the recipe during substrate fallback) does
    /// not duplicate entries. Validators are merged by goal; other collections
    /// only gain entries they don't already contain.
    pub fn apply_to_recipe(&self, recipe: &mut RehostingRecipe) {
        if let Some(machine) = &self.qemu_machine {
            recipe.qemu_machine = Some(machine.clone());
        }
        if self.network_mode.is_some()
            || self.network_interface.is_some()
            || self.network_fallback_ip.is_some()
        {
            recipe.network = Some(RecipeNetworkConfig {
                interface: self.network_interface.clone(),
                mode: self.network_mode.clone(),
                fallback_ip: self.network_fallback_ip.clone(),
            });
        }
        for partition in &self.partition_roles {
            let materialization = RecipePartitionMaterialization::new(
                partition.source.clone(),
                partition.mount.clone(),
                partition
                    .materialization
                    .clone()
                    .unwrap_or_else(|| "staged-copy".to_string()),
            );
            if !recipe.partition_materializations.contains(&materialization) {
                recipe.partition_materializations.push(materialization);
            }
        }
        for validator in &self.extra_validators {
            if let Some(existing) = recipe
                .validators
                .iter_mut()
                .find(|existing| existing.goal == validator.goal)
            {
                *existing = validator.clone();
            } else {
                recipe.validators.push(validator.clone());
            }
        }
        for transform in &self.materialize_transforms {
            if !recipe.filesystem_transforms.contains(transform) {
                recipe.filesystem_transforms.push(transform.clone());
            }
        }
        for command in &self.command_shims {
            if !recipe.guest_adaptations.command_shims.contains(command) {
                recipe.guest_adaptations.command_shims.push(command.clone());
            }
        }
        for pattern in &self.module_skip_patterns {
            if !recipe
                .guest_adaptations
                .module_skip_patterns
                .contains(pattern)
            {
                recipe
                    .guest_adaptations
                    .module_skip_patterns
                    .push(pattern.clone());
            }
        }
        for caveat in &self.caveats {
            if !recipe.fidelity_caveats.contains(caveat) {
                recipe.fidelity_caveats.push(caveat.clone());
            }
        }
        let capability = self.capability_report();
        if !capability.supported_actions.is_empty()
            || !capability.unsupported_actions.is_empty()
            || !capability.degraded_actions.is_empty()
        {
            recipe.rehosting_capability = Some(capability);
        }
    }

    pub fn capability_report(&self) -> RehostingCapabilityReport {
        let mut report = RehostingCapabilityReport {
            pack_id: self.pack_id.clone(),
            pack_version: self.pack_version.clone(),
            data_version: runtime_data_version(),
            caveats: self.caveats.clone(),
            ..RehostingCapabilityReport::default()
        };
        if self.qemu_machine.is_some() {
            report.supported_actions.push("qemu-machine".into());
        }
        if let Some(substrate) = &self.requested_substrate {
            report
                .supported_actions
                .push(format!("substrate:{substrate}"));
        }
        for partition in &self.partition_roles {
            report.unsupported_actions.push(format!(
                "partition:{}:{}",
                partition.source, partition.mount
            ));
        }
        for validator in &self.extra_validators {
            let action = format!("validator:{}", validator.validator_kind);
            if validator.validator_kind == "manual" {
                report.degraded_actions.push(action);
            } else {
                report.supported_actions.push(action);
            }
        }
        for transform in &self.materialize_transforms {
            report.supported_actions.push(format!(
                "materialize:{}:{}",
                match transform.destination_kind {
                    crate::rehosting_recipe::RecipePathKind::File => "file",
                    crate::rehosting_recipe::RecipePathKind::Directory => "directory",
                },
                transform.destination
            ));
        }
        if self.network_mode.is_some()
            || self.network_interface.is_some()
            || self.network_fallback_ip.is_some()
        {
            report.degraded_actions.push(
                "network configuration is recorded but backend fidelity remains experimental"
                    .into(),
            );
        }
        report
            .unsupported_actions
            .extend(self.skip_flags.iter().cloned());
        report
    }
}

fn runtime_data_version() -> Option<String> {
    let resolver = crate::data_dir::DataResolver::for_current_process(None);
    for relative in ["manifest.json", "share/fat/manifest.json"] {
        if let Ok(resolved) = resolver.resolve_required(relative) {
            if let Ok(manifest) = crate::data_manifest::DataManifest::load(
                resolved.path.parent().unwrap_or(&resolved.root),
            ) {
                return Some(manifest.data_version);
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rehosting_pack::parse_rehosting_pack_yaml;
    use crate::rehosting_policy::{SubstrateKind, SubstratePreference};
    use crate::rehosting_recipe::RehostingRecipe;

    fn full_pack() -> RehostingPack {
        parse_rehosting_pack_yaml(
            r#"
id: acme/router
kind: rehosting-pack
version: "0.1"
runtime:
  qemu_machine: versatilepb
  network:
    interface: eth0
    mode: dhcp
    fallback_ip: 10.0.2.15
partitions:
  roles:
    - source: rootfs
      mount: /
      materialization: staged-copy
    - source: app
      mount: /system
      materialization: staged-copy
repairs:
  init:
    skip_module_loads_matching:
      - "vendor_gpio"
    skip_commands:
      - "devmem"
    materialize_paths:
      - "/configs"
validators:
  - goal: shell-access
    kind: serial-log-pattern
    pattern: "init complete"
  - goal: http-listener
    kind: http
    port: 80
caveats:
  - "no camera ISP fidelity"
"#,
        )
        .expect("parse pack")
    }

    fn empty_recipe() -> RehostingRecipe {
        RehostingRecipe::new(
            "target",
            "model",
            "run",
            "emulate firmware",
            SubstratePreference::Auto,
            SubstrateKind::System,
        )
    }

    #[test]
    fn from_pack_translates_every_section() {
        let overlay = PackOverlay::from_pack(&full_pack());
        assert_eq!(overlay.pack_id, "acme/router");
        assert_eq!(overlay.qemu_machine.as_deref(), Some("versatilepb"));
        assert_eq!(overlay.network_mode.as_deref(), Some("dhcp"));
        assert_eq!(overlay.network_fallback_ip.as_deref(), Some("10.0.2.15"));
        assert_eq!(overlay.extra_validators.len(), 2);
        assert_eq!(
            overlay.extra_validators[0].pattern.as_deref(),
            Some("init complete")
        );
        assert_eq!(overlay.extra_validators[1].port, Some(80));
        assert_eq!(overlay.materialize_transforms.len(), 1);
        assert_eq!(
            overlay.skip_flags,
            vec![
                "repair:skip-command:devmem".to_string(),
                "repair:skip-module:vendor_gpio".to_string(),
            ]
        );
        assert_eq!(overlay.caveats, vec!["no camera ISP fidelity".to_string()]);
        assert!(overlay
            .applied
            .iter()
            .any(|line| line.contains("versatilepb")));
    }

    #[test]
    fn apply_to_recipe_sets_machine_and_merges_collections() {
        let overlay = PackOverlay::from_pack(&full_pack());
        let mut recipe = empty_recipe();
        overlay.apply_to_recipe(&mut recipe);

        assert_eq!(recipe.qemu_machine.as_deref(), Some("versatilepb"));
        assert_eq!(recipe.partition_materializations.len(), 2);
        assert_eq!(recipe.partition_materializations[0].source_role, "rootfs");
        assert_eq!(recipe.partition_materializations[0].destination, "/");
        assert_eq!(recipe.partition_materializations[1].strategy, "staged-copy");
        assert_eq!(recipe.validators.len(), 2);
        assert_eq!(
            recipe.network.as_ref().unwrap().interface.as_deref(),
            Some("eth0")
        );
        assert_eq!(
            recipe.network.as_ref().unwrap().mode.as_deref(),
            Some("dhcp")
        );
        assert_eq!(recipe.filesystem_transforms.len(), 1);
        assert_eq!(
            recipe.filesystem_transforms[0].transform_kind,
            "materialize"
        );
        assert_eq!(
            recipe.filesystem_transforms[0].destination_kind,
            crate::rehosting_recipe::RecipePathKind::Directory
        );
        assert_eq!(recipe.guest_adaptations.command_shims, vec!["devmem"]);
        assert_eq!(
            recipe.guest_adaptations.module_skip_patterns,
            vec!["vendor_gpio"]
        );
        assert!(recipe.instrumentation_flags.is_empty());
        assert_eq!(recipe.fidelity_caveats.len(), 1);
        let capability = recipe.rehosting_capability.as_ref().unwrap();
        assert!(capability
            .unsupported_actions
            .iter()
            .any(|action| action.contains("skip-command")));
    }

    #[test]
    fn apply_to_recipe_pack_validator_overrides_derived_validator_by_goal() {
        let overlay = PackOverlay::from_pack(&full_pack());
        let mut recipe = empty_recipe();
        recipe
            .validators
            .push(RecipeValidator::new("shell-access", "existing-kind"));
        overlay.apply_to_recipe(&mut recipe);
        let shell = recipe
            .validators
            .iter()
            .find(|v| v.goal == "shell-access")
            .expect("shell validator");
        assert_eq!(shell.validator_kind, "serial-log-pattern");
        assert_eq!(shell.pattern.as_deref(), Some("init complete"));
        assert!(recipe.validators.iter().any(|v| v.goal == "http-listener"));
    }

    #[test]
    fn apply_to_recipe_is_idempotent() {
        let overlay = PackOverlay::from_pack(&full_pack());
        let mut recipe = empty_recipe();
        overlay.apply_to_recipe(&mut recipe);
        let after_first = recipe.clone();
        overlay.apply_to_recipe(&mut recipe);
        assert_eq!(
            recipe, after_first,
            "re-applying must not duplicate entries"
        );
    }

    #[test]
    fn empty_pack_produces_no_overrides() {
        let pack =
            parse_rehosting_pack_yaml("id: bare/pack\nkind: rehosting-pack\nversion: \"0.1\"\n")
                .unwrap();
        let overlay = PackOverlay::from_pack(&pack);
        let mut recipe = empty_recipe();
        let before = recipe.clone();
        overlay.apply_to_recipe(&mut recipe);
        assert_eq!(recipe, before, "no pack sections → no changes");
        assert!(overlay.applied.is_empty());
    }

    #[test]
    fn recipe_serde_roundtrips_with_and_without_machine() {
        let mut recipe = empty_recipe();
        let json = serde_json::to_string(&recipe).unwrap();
        assert_eq!(
            serde_json::from_str::<RehostingRecipe>(&json).unwrap(),
            recipe
        );

        recipe.qemu_machine = Some("malta".to_string());
        let json = serde_json::to_string(&recipe).unwrap();
        assert!(json.contains("malta"));
        assert_eq!(
            serde_json::from_str::<RehostingRecipe>(&json).unwrap(),
            recipe
        );
    }

    #[test]
    fn capability_report_accounts_for_substrate_partitions_and_manual_validation() {
        let pack = parse_rehosting_pack_yaml(
            r#"
id: acme/system-pack
kind: rehosting-pack
version: "0.1"
partitions:
  roles:
    - source: app
      mount: /system
      materialization: staged-copy
runtime:
  substrate: system
validators:
  - goal: operator-check
    kind: manual
caveats: ["experimental fixture"]
"#,
        )
        .unwrap();

        let report = PackOverlay::from_pack(&pack).capability_report();

        assert!(report
            .supported_actions
            .iter()
            .any(|action| action == "substrate:system"));
        assert!(report
            .unsupported_actions
            .iter()
            .any(|action| action.contains("partition:app:/system")));
        assert!(report
            .degraded_actions
            .iter()
            .any(|action| action.contains("validator:manual")));
        assert!(report.is_degraded());
    }
}
