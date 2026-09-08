use fat_core::inventory::{AnalysisSnapshot, BinaryRecord};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BinaryInventory {
    binaries: Vec<BinaryRecord>,
}

impl BinaryInventory {
    pub fn new(binaries: Vec<BinaryRecord>) -> Self {
        Self { binaries }
    }

    pub fn from_snapshot(snapshot: &AnalysisSnapshot) -> Self {
        Self::new(snapshot.binaries.clone())
    }

    pub fn binaries(&self) -> &[BinaryRecord] {
        &self.binaries
    }
}
