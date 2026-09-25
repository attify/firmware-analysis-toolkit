//! Documented names attached to static code evidence, not runtime observations.
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterSource {
    pub title: String,
    pub url: String,
    pub location: String,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterName {
    pub peripheral: String,
    pub register: String,
    /// read-only, write-only, or read-write from the documentation.
    pub documented_access: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub condition: Option<String>,
    pub source: RegisterSource,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterAccessAnnotation {
    pub instruction_address: u32,
    pub instruction_offset: u64,
    pub target: u32,
    pub access: String,
    pub width_bytes: u8,
    /// Multiple names preserve unresolved aliases (e.g. UART DLAB).
    pub names: Vec<RegisterName>,
    pub notes: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterAddressReference {
    pub instruction_address: u32,
    pub instruction_offset: u64,
    pub pool_address: u32,
    pub pool_offset: u64,
    pub value: u32,
    /// Loading an address constant does not establish a peripheral access.
    pub names: Vec<RegisterName>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegisterAnnotationReport {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub family_profile: Option<String>,
    pub profile_selection: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub core_name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub core_source: Option<RegisterSource>,
    pub accesses: Vec<RegisterAccessAnnotation>,
    pub address_references: Vec<RegisterAddressReference>,
    pub notes: Vec<String>,
}
