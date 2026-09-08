pub mod dispatch;
pub mod registry;

use fat_plugin_api::{AnalysisTrigger, PluginDescriptor};

pub use dispatch::{dispatch_run_analysis, dispatch_target_analysis};
pub use registry::PluginRegistry;

pub fn supports_trigger(descriptor: &PluginDescriptor, trigger: AnalysisTrigger) -> bool {
    descriptor.supported_triggers.contains(&trigger)
}
