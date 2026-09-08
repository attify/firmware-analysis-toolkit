use fat_core::inventory::AnalysisSnapshot;
use fat_plugin_api::{
    AnalysisRequest, AnalysisResult, AnalysisTrigger, AnalyzerPlugin, PluginDescriptor,
};

use crate::request::NormalizedAnalysisRequest;

pub trait Analyzer: Send + Sync {
    fn descriptor(&self) -> PluginDescriptor;

    fn analyze(&self, request: &NormalizedAnalysisRequest) -> AnalysisResult;
}

#[derive(Default)]
pub struct AnalyzerRegistry {
    analyzers: Vec<Box<dyn Analyzer>>,
}

impl AnalyzerRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register<A>(&mut self, analyzer: A)
    where
        A: Analyzer + 'static,
    {
        self.analyzers.push(Box::new(analyzer));
    }

    pub fn analyzers(&self) -> &[Box<dyn Analyzer>] {
        &self.analyzers
    }

    pub fn analyzers_for_trigger(
        &self,
        trigger: AnalysisTrigger,
    ) -> impl Iterator<Item = &dyn Analyzer> {
        self.analyzers
            .iter()
            .filter(move |analyzer| analyzer.descriptor().supported_triggers.contains(&trigger))
            .map(|analyzer| analyzer.as_ref())
    }

    pub fn descriptors(&self) -> Vec<PluginDescriptor> {
        self.analyzers
            .iter()
            .map(|analyzer| analyzer.descriptor())
            .collect()
    }
}

pub struct AnalysisEngine {
    registry: AnalyzerRegistry,
}

impl AnalysisEngine {
    pub fn new(registry: AnalyzerRegistry) -> Self {
        Self { registry }
    }

    pub fn registry(&self) -> &AnalyzerRegistry {
        &self.registry
    }

    pub fn analyze(&self, snapshot: AnalysisSnapshot) -> AnalysisSnapshot {
        let mut result = snapshot.clone();
        let request = NormalizedAnalysisRequest::for_snapshot(snapshot);
        let analysis_result = self.analyze_request(&request);
        if !analysis_result.findings.is_empty() {
            result.findings.extend(analysis_result.findings);
        }
        result
    }

    pub fn analyze_request(&self, request: &NormalizedAnalysisRequest) -> AnalysisResult {
        let mut merged = AnalysisResult::default();
        for analyzer in self.registry.analyzers_for_trigger(request.request.trigger) {
            let result = analyzer.analyze(request);
            merged.findings.extend(result.findings);
            merged.diagnostics.extend(result.diagnostics);
            merged.produced_artifacts.extend(result.produced_artifacts);
            merged
                .produced_artifact_ids
                .extend(result.produced_artifact_ids);
        }
        merged
    }

    pub fn analyzer_ids(&self) -> Vec<String> {
        self.registry
            .descriptors()
            .iter()
            .map(|descriptor| descriptor.plugin_id.clone())
            .collect()
    }
}

pub struct BuiltInAnalyzerPlugin<A> {
    analyzer: A,
}

impl<A> BuiltInAnalyzerPlugin<A> {
    pub fn new(analyzer: A) -> Self {
        Self { analyzer }
    }
}

impl<A> AnalyzerPlugin for BuiltInAnalyzerPlugin<A>
where
    A: Analyzer,
{
    fn descriptor(&self) -> PluginDescriptor {
        self.analyzer.descriptor()
    }

    fn analyze(&self, request: &AnalysisRequest) -> AnalysisResult {
        self.analyzer.analyze(&NormalizedAnalysisRequest {
            request: request.clone(),
            snapshot: None,
            artifact_documents: Vec::new(),
            diagnostics: Vec::new(),
            historical_diagnostics: Vec::new(),
        })
    }
}
