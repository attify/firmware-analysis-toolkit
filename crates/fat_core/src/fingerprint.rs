#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FirmwareFingerprint {
    pub sha256: String,
    pub size_bytes: u64,
}

impl FirmwareFingerprint {
    pub fn new(sha256: String, size_bytes: u64) -> Self {
        Self { sha256, size_bytes }
    }
}
