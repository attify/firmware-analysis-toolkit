use crate::finding::Finding;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Architecture {
    Armel,
    Arm,
    Arm64,
    Mips,
    Mipsel,
    Riscv64,
    X86,
    X86_64,
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BinaryRecord {
    pub id: String,
    pub name: String,
    pub rel_path: String,
    pub architecture: Architecture,
    pub nx: Option<bool>,
    pub pie: Option<bool>,
    pub canary: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AnalysisSnapshot {
    pub binaries: Vec<BinaryRecord>,
    pub findings: Vec<Finding>,
}
