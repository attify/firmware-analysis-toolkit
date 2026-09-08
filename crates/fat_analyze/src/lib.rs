pub mod analyzers;
pub mod binary;
pub mod binary_diff;
pub mod bootloader;
pub mod cert_diff;
pub mod credential;
pub mod edge_ai;
pub mod engine;
pub mod firmware_formats;
pub mod image_measurements;
pub mod inventory;
pub mod loader;
pub mod mcu;
pub mod mcu_family;
pub mod mcu_init_handler;
pub mod mcu_init_table;
pub mod mcu_inspect;
pub mod mcu_sram;
pub mod mcu_system_init;
pub mod mcu_thumb;
pub mod nvram_diff;
pub mod request;
pub mod string_diff;
pub mod svd_rank;

use analyzers::{
    BinarySecurityAnalyzer, ConfigStaticAnalyzer, CredentialStaticAnalyzer, DLCModelAnalyzer,
    FailureClusteringAnalyzer, MagikModelAnalyzer, OnnxModelAnalyzer, ServiceRuntimeAnalyzer,
    TFLiteModelAnalyzer, WebSurfaceStaticAnalyzer,
};

pub use engine::{AnalysisEngine, Analyzer, AnalyzerRegistry, BuiltInAnalyzerPlugin};
pub use request::NormalizedAnalysisRequest;

pub fn built_in_registry() -> AnalyzerRegistry {
    let mut registry = AnalyzerRegistry::new();
    registry.register(BinarySecurityAnalyzer);
    registry.register(CredentialStaticAnalyzer);
    registry.register(ConfigStaticAnalyzer);
    registry.register(WebSurfaceStaticAnalyzer);
    registry.register(ServiceRuntimeAnalyzer);
    registry.register(FailureClusteringAnalyzer);
    registry.register(MagikModelAnalyzer);
    registry.register(TFLiteModelAnalyzer);
    registry.register(OnnxModelAnalyzer);
    registry.register(DLCModelAnalyzer);
    registry
}

pub fn built_in_engine() -> AnalysisEngine {
    AnalysisEngine::new(built_in_registry())
}
