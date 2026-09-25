//! Bounded static code candidates. These observations do not establish execution.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct McuCodeReport {
    pub instruction_count: usize,
    pub block_count: usize,
    pub instruction_budget: usize,
    pub block_budget: usize,
    pub function_budget: usize,
    pub budget_exhausted: bool,
    pub instruction_ranges: Vec<CodeInstructionRange>,
    pub function_candidates: Vec<CodeFunctionCandidate>,
    pub flow_edges: Vec<CodeFlowEdge>,
    pub literal_references: Vec<CodeLiteralReference>,
    pub string_references: Vec<CodeStringReference>,
    pub memory_accesses: Vec<CodeMemoryAccess>,
    pub initialization: Vec<CodeInitialization>,
    pub stops: Vec<CodeStop>,
    pub notes: Vec<String>,
}

/// Adjacent decoded instructions, not a claim that the entire region executes.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeInstructionRange {
    pub address: u32,
    pub file_offset: u64,
    pub length: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeFunctionCandidate {
    pub address: u32,
    pub file_offset: u64,
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeFlowEdge {
    pub instruction_address: u32,
    pub target: Option<u32>,
    /// Direct call/branch, conditional branch, unresolved call, or return.
    pub kind: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeLiteralReference {
    pub instruction_address: u32,
    pub instruction_offset: u64,
    pub pool_address: u32,
    pub pool_offset: u64,
    pub value: u32,
}

/// A literal load references bytes which parse as a terminated string. Usage is unknown.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeStringReference {
    pub instruction_address: u32,
    pub address: u32,
    pub file_offset: u64,
    pub encoding: String,
    pub value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum MemoryAccessKind {
    Read,
    Write,
}

/// Effective address resolved only from constants within one basic block.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeMemoryAccess {
    pub instruction_address: u32,
    pub instruction_offset: u64,
    pub target: u32,
    pub access: MemoryAccessKind,
    pub width_bytes: u8,
}

/// Summary of an already recovered startup descriptor, not proof of a runtime write.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeInitialization {
    pub record_address: u32,
    pub kind: String,
    pub source: Option<u32>,
    pub destination: u32,
    pub length: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CodeStop {
    pub address: u32,
    pub reason: String,
}
