use fat_plugin_api::{AnalysisRequest, AnalysisResult, AnalyzerPlugin, PluginDescriptor};

#[derive(Default)]
pub struct PluginRegistry {
    plugins: Vec<Box<dyn AnalyzerPlugin>>,
}

impl PluginRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register<P>(&mut self, plugin: P)
    where
        P: AnalyzerPlugin + 'static,
    {
        self.plugins.push(Box::new(plugin));
    }

    pub fn plugins(&self) -> &[Box<dyn AnalyzerPlugin>] {
        &self.plugins
    }

    pub fn descriptors(&self) -> Vec<PluginDescriptor> {
        self.plugins
            .iter()
            .map(|plugin| plugin.descriptor())
            .collect()
    }

    pub fn plugin(&self, plugin_id: &str) -> Option<&dyn AnalyzerPlugin> {
        self.plugins
            .iter()
            .find(|plugin| plugin.descriptor().plugin_id == plugin_id)
            .map(|plugin| plugin.as_ref())
    }

    pub fn run(&self, plugin_id: &str, request: &AnalysisRequest) -> Option<AnalysisResult> {
        self.plugin(plugin_id).map(|plugin| plugin.analyze(request))
    }
}
