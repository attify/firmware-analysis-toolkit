use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::ids::stable_prefixed_id;
use crate::rehosting_policy::{SubstrateKind, SubstratePreference};

/// A single hook target for QEMU TCG plugin instrumentation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookSpec {
    /// Guest virtual address to hook.
    pub address: u64,
    /// Human-readable name (e.g. "system", "nvram_get").
    pub name: String,
    /// Which argument registers to dereference as null-terminated strings.
    /// Uses MIPS register names: "a0", "a1", "a2", "a3".
    #[serde(default)]
    pub string_args: Vec<String>,
}

/// Typed configuration for QEMU TCG plugin instrumentation.
/// Replaces the previous string-tunneled "instrument:..." protocol.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstrumentationConfig {
    /// Absolute path to the compiled plugin shared object (fat-hook.so).
    pub plugin_path: PathBuf,
    /// Resolved hook definitions — parsed from the YAML config file.
    pub hooks: Vec<HookSpec>,
    /// Whether to emit JSONL trace output (default: true).
    #[serde(default = "default_true")]
    pub json_output: bool,
}

fn default_true() -> bool {
    true
}

impl InstrumentationConfig {
    /// Generate the QEMU `-plugin` argument string for this config.
    /// Passes hooks as repeated `hook=` CLI args to keep the C plugin stateless.
    pub fn plugin_arg(&self, trace_log_path: &str) -> String {
        let mut parts = vec![self.plugin_path.display().to_string()];

        for hook in &self.hooks {
            let mut entry = format!("hook=0x{:08x}:{}", hook.address, hook.name);
            // Build a bitmask from the explicit register list.
            // bit 0 = a0, bit 1 = a1, bit 2 = a2, bit 3 = a3.
            let mask = Self::string_args_to_mask(&hook.string_args);
            if mask != 0 {
                entry.push_str(&format!(":m{mask:x}"));
            }
            parts.push(entry);
        }

        parts.push(format!("log={trace_log_path}"));
        if self.json_output {
            parts.push("format=json".to_string());
        }

        parts.join(",")
    }

    /// Convert a list of register names to a 4-bit bitmask.
    fn string_args_to_mask(args: &[String]) -> u8 {
        let mut mask: u8 = 0;
        for arg in args {
            match arg.as_str() {
                "a0" => mask |= 1 << 0,
                "a1" => mask |= 1 << 1,
                "a2" => mask |= 1 << 2,
                "a3" => mask |= 1 << 3,
                _ => {}
            }
        }
        mask
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RecipePathKind {
    #[default]
    File,
    Directory,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipeFilesystemTransform {
    pub transform_kind: String,
    pub source: String,
    pub destination: String,
    #[serde(default)]
    pub destination_kind: RecipePathKind,
}

impl RecipeFilesystemTransform {
    pub fn new(
        transform_kind: impl Into<String>,
        source: impl Into<String>,
        destination: impl Into<String>,
    ) -> Self {
        Self {
            transform_kind: transform_kind.into(),
            source: source.into(),
            destination: destination.into(),
            destination_kind: RecipePathKind::File,
        }
    }

    pub fn directory(transform_kind: impl Into<String>, destination: impl Into<String>) -> Self {
        let destination = destination.into();
        Self {
            transform_kind: transform_kind.into(),
            source: destination.clone(),
            destination,
            destination_kind: RecipePathKind::Directory,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipeDeviceNodePlan {
    pub path: String,
    pub node_kind: String,
}

impl RecipeDeviceNodePlan {
    pub fn new(path: impl Into<String>, node_kind: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            node_kind: node_kind.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipeLaunchPlan {
    pub executable: String,
    pub argv: Vec<String>,
}

impl RecipeLaunchPlan {
    pub fn new(executable: impl Into<String>, argv: Vec<String>) -> Self {
        Self {
            executable: executable.into(),
            argv,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipeValidator {
    pub goal: String,
    pub validator_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub port: Option<u16>,
}

impl RecipeValidator {
    pub fn new(goal: impl Into<String>, validator_kind: impl Into<String>) -> Self {
        Self {
            goal: goal.into(),
            validator_kind: validator_kind.into(),
            pattern: None,
            name: None,
            path: None,
            port: None,
        }
    }

    pub fn with_pattern(mut self, pattern: impl Into<String>) -> Self {
        self.pattern = Some(pattern.into());
        self
    }

    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    pub fn with_path(mut self, path: impl Into<String>) -> Self {
        self.path = Some(path.into());
        self
    }

    pub fn with_port(mut self, port: u16) -> Self {
        self.port = Some(port);
        self
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipeNetworkConfig {
    pub interface: Option<String>,
    pub mode: Option<String>,
    pub fallback_ip: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipePartitionMaterialization {
    pub source_role: String,
    pub destination: String,
    pub strategy: String,
}

impl RecipePartitionMaterialization {
    pub fn new(
        source_role: impl Into<String>,
        destination: impl Into<String>,
        strategy: impl Into<String>,
    ) -> Self {
        Self {
            source_role: source_role.into(),
            destination: destination.into(),
            strategy: strategy.into(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecipeGuestAdaptations {
    #[serde(default)]
    pub command_shims: Vec<String>,
    #[serde(default)]
    pub module_skip_patterns: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RehostingCapabilityReport {
    pub pack_id: String,
    pub pack_version: String,
    pub data_version: Option<String>,
    pub supported_actions: Vec<String>,
    pub unsupported_actions: Vec<String>,
    pub degraded_actions: Vec<String>,
    pub caveats: Vec<String>,
}

impl RehostingCapabilityReport {
    pub fn is_degraded(&self) -> bool {
        !self.unsupported_actions.is_empty() || !self.degraded_actions.is_empty()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RehostingRecipe {
    pub rehosting_recipe_id: String,
    pub target_id: String,
    pub target_model_id: String,
    pub run_id: String,
    pub goal: String,
    pub substrate_preference: SubstratePreference,
    pub selected_substrate: SubstrateKind,
    pub selected_backend: Option<String>,
    #[serde(default)]
    pub partition_materializations: Vec<RecipePartitionMaterialization>,
    #[serde(default)]
    pub guest_adaptations: RecipeGuestAdaptations,
    pub filesystem_transforms: Vec<RecipeFilesystemTransform>,
    pub env_injections: Vec<String>,
    pub device_nodes: Vec<RecipeDeviceNodePlan>,
    pub launch_plan: Option<RecipeLaunchPlan>,
    pub validators: Vec<RecipeValidator>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub network: Option<RecipeNetworkConfig>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rehosting_capability: Option<RehostingCapabilityReport>,
    pub retry_budget: u32,
    pub instrumentation_flags: Vec<String>,
    pub fidelity_caveats: Vec<String>,
    /// Explicit QEMU `-M <machine>` override, e.g. supplied by a rehosting pack.
    /// When `None` the system runner derives the machine from the architecture.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub qemu_machine: Option<String>,
    /// Typed TCG plugin instrumentation config. When set, the system runner
    /// appends `-plugin` args to the QEMU command line.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub instrumentation: Option<InstrumentationConfig>,
}

impl RehostingRecipe {
    pub fn new(
        target_id: impl Into<String>,
        target_model_id: impl Into<String>,
        run_id: impl Into<String>,
        goal: impl Into<String>,
        substrate_preference: SubstratePreference,
        selected_substrate: SubstrateKind,
    ) -> Self {
        let target_id = target_id.into();
        let target_model_id = target_model_id.into();
        let run_id = run_id.into();
        let goal = goal.into();
        let rehosting_recipe_id = stable_prefixed_id(
            "rhrecipe",
            [
                target_id.as_str(),
                target_model_id.as_str(),
                run_id.as_str(),
                goal.as_str(),
                substrate_preference.as_str(),
                selected_substrate.as_str(),
            ],
        );

        Self {
            rehosting_recipe_id,
            target_id,
            target_model_id,
            run_id,
            goal,
            substrate_preference,
            selected_substrate,
            selected_backend: None,
            partition_materializations: Vec::new(),
            guest_adaptations: RecipeGuestAdaptations::default(),
            filesystem_transforms: Vec::new(),
            env_injections: Vec::new(),
            device_nodes: Vec::new(),
            launch_plan: None,
            validators: Vec::new(),
            network: None,
            rehosting_capability: None,
            retry_budget: 0,
            instrumentation_flags: Vec::new(),
            fidelity_caveats: Vec::new(),
            qemu_machine: None,
            instrumentation: None,
        }
    }

    pub fn with_selected_backend(mut self, selected_backend: impl Into<String>) -> Self {
        self.selected_backend = Some(selected_backend.into());
        self
    }

    pub fn with_qemu_machine(mut self, qemu_machine: impl Into<String>) -> Self {
        self.qemu_machine = Some(qemu_machine.into());
        self
    }

    pub fn with_partition_materializations(
        mut self,
        partition_materializations: Vec<RecipePartitionMaterialization>,
    ) -> Self {
        self.partition_materializations = partition_materializations;
        self
    }

    pub fn with_guest_adaptations(mut self, guest_adaptations: RecipeGuestAdaptations) -> Self {
        self.guest_adaptations = guest_adaptations;
        self
    }

    pub fn with_filesystem_transforms(
        mut self,
        filesystem_transforms: Vec<RecipeFilesystemTransform>,
    ) -> Self {
        self.filesystem_transforms = filesystem_transforms;
        self
    }

    pub fn with_env_injections(mut self, env_injections: Vec<String>) -> Self {
        self.env_injections = env_injections;
        self
    }

    pub fn with_device_nodes(mut self, device_nodes: Vec<RecipeDeviceNodePlan>) -> Self {
        self.device_nodes = device_nodes;
        self
    }

    pub fn with_launch_plan(mut self, launch_plan: RecipeLaunchPlan) -> Self {
        self.launch_plan = Some(launch_plan);
        self
    }

    pub fn with_validators(mut self, validators: Vec<RecipeValidator>) -> Self {
        self.validators = validators;
        self
    }

    pub fn with_retry_budget(mut self, retry_budget: u32) -> Self {
        self.retry_budget = retry_budget;
        self
    }

    pub fn with_instrumentation_flags(mut self, instrumentation_flags: Vec<String>) -> Self {
        self.instrumentation_flags = instrumentation_flags;
        self
    }

    pub fn with_fidelity_caveats(mut self, fidelity_caveats: Vec<String>) -> Self {
        self.fidelity_caveats = fidelity_caveats;
        self
    }

    pub fn with_instrumentation(mut self, instrumentation: InstrumentationConfig) -> Self {
        self.instrumentation = Some(instrumentation);
        self
    }
}

impl SubstrateKind {
    pub fn as_str(self) -> &'static str {
        match self {
            SubstrateKind::Service => "service",
            SubstrateKind::System => "system",
            SubstrateKind::Reference => "reference",
        }
    }
}

impl SubstratePreference {
    pub fn as_str(self) -> &'static str {
        match self {
            SubstratePreference::ServiceFirst => "service-first",
            SubstratePreference::SystemFirst => "system-first",
            SubstratePreference::ReferenceOnly => "reference-only",
            SubstratePreference::Auto => "auto",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hook(name: &str, addr: u64, string_args: &[&str]) -> HookSpec {
        HookSpec {
            address: addr,
            name: name.to_string(),
            string_args: string_args.iter().map(|s| s.to_string()).collect(),
        }
    }

    #[test]
    fn string_args_to_mask_empty() {
        assert_eq!(InstrumentationConfig::string_args_to_mask(&[]), 0);
    }

    #[test]
    fn string_args_to_mask_a0_only() {
        let args = vec!["a0".to_string()];
        assert_eq!(InstrumentationConfig::string_args_to_mask(&args), 0x1);
    }

    #[test]
    fn string_args_to_mask_a1_only() {
        let args = vec!["a1".to_string()];
        assert_eq!(InstrumentationConfig::string_args_to_mask(&args), 0x2);
    }

    #[test]
    fn string_args_to_mask_a0_a2_noncontiguous() {
        let args = vec!["a0".to_string(), "a2".to_string()];
        assert_eq!(InstrumentationConfig::string_args_to_mask(&args), 0x5);
    }

    #[test]
    fn string_args_to_mask_all_four() {
        let args: Vec<String> = vec!["a0", "a1", "a2", "a3"]
            .into_iter()
            .map(String::from)
            .collect();
        assert_eq!(InstrumentationConfig::string_args_to_mask(&args), 0xf);
    }

    #[test]
    fn string_args_to_mask_ignores_unknown() {
        let args = vec!["a0".to_string(), "v0".to_string(), "sp".to_string()];
        assert_eq!(InstrumentationConfig::string_args_to_mask(&args), 0x1);
    }

    #[test]
    fn plugin_arg_no_hooks() {
        let cfg = InstrumentationConfig {
            plugin_path: PathBuf::from("/path/to/fat-hook.so"),
            hooks: vec![],
            json_output: true,
        };
        let arg = cfg.plugin_arg("/tmp/trace.jsonl");
        assert!(arg.starts_with("/path/to/fat-hook.so,"));
        assert!(arg.contains("log=/tmp/trace.jsonl"));
        assert!(arg.contains("format=json"));
        assert!(!arg.contains("hook="));
    }

    #[test]
    fn plugin_arg_hook_without_string_args() {
        let cfg = InstrumentationConfig {
            plugin_path: PathBuf::from("fat-hook.so"),
            hooks: vec![hook("hw_reg", 0x0043a070, &[])],
            json_output: false,
        };
        let arg = cfg.plugin_arg("/tmp/t.jsonl");
        assert!(arg.contains("hook=0x0043a070:hw_reg,"));
        assert!(!arg.contains(":m"));
        assert!(!arg.contains("format=json"));
    }

    #[test]
    fn plugin_arg_hook_a0_only() {
        let cfg = InstrumentationConfig {
            plugin_path: PathBuf::from("fat-hook.so"),
            hooks: vec![hook("system", 0x00412345, &["a0"])],
            json_output: true,
        };
        let arg = cfg.plugin_arg("/tmp/t.jsonl");
        assert!(arg.contains("hook=0x00412345:system:m1"));
    }

    #[test]
    fn plugin_arg_hook_a1_only() {
        let cfg = InstrumentationConfig {
            plugin_path: PathBuf::from("fat-hook.so"),
            hooks: vec![hook("popen", 0x00412345, &["a1"])],
            json_output: true,
        };
        let arg = cfg.plugin_arg("/tmp/t.jsonl");
        assert!(arg.contains(":m2"));
    }

    #[test]
    fn plugin_arg_hook_noncontiguous_a0_a2() {
        let cfg = InstrumentationConfig {
            plugin_path: PathBuf::from("fat-hook.so"),
            hooks: vec![hook("custom", 0x00400000, &["a0", "a2"])],
            json_output: true,
        };
        let arg = cfg.plugin_arg("/tmp/t.jsonl");
        assert!(arg.contains(":m5"), "expected :m5 in {arg}");
    }

    #[test]
    fn plugin_arg_hook_all_four() {
        let cfg = InstrumentationConfig {
            plugin_path: PathBuf::from("fat-hook.so"),
            hooks: vec![hook("all", 0x00400000, &["a0", "a1", "a2", "a3"])],
            json_output: true,
        };
        let arg = cfg.plugin_arg("/tmp/t.jsonl");
        assert!(arg.contains(":mf"), "expected :mf in {arg}");
    }
}
