//! Located FIT metadata. Signature nodes describe stored metadata, not verification results.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FitScanReport {
    pub blobs: Vec<FitBlob>,
    pub control_keys: Vec<FitControlKey>,
    pub diagnostics: Vec<FitDiagnostic>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FitBlob {
    pub offset: u64,
    pub size: u64,
    /// False when metadata is malformed or analysis limits prevent a complete interpretation.
    pub complete: bool,
    pub description: Option<String>,
    pub default_configuration: Option<String>,
    pub images: Vec<FitImage>,
    pub configurations: Vec<FitConfiguration>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FitImage {
    pub name: String,
    pub node_path: String,
    pub offset: u64,
    pub hashes: Vec<FitHash>,
    pub signatures: Vec<FitSignature>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FitConfiguration {
    pub name: String,
    pub node_path: String,
    pub offset: u64,
    pub references: Vec<FitReference>,
    pub hashes: Vec<FitHash>,
    pub signatures: Vec<FitSignature>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FitReference {
    pub property: String,
    pub images: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FitHash {
    pub node_path: String,
    pub offset: u64,
    pub algorithm: Option<String>,
    /// Configuration hash declarations may omit a value; component-image hashes require one.
    pub value_hex: Option<String>,
    pub value_size: u64,
    pub value_truncated: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FitSignature {
    pub node_path: String,
    pub offset: u64,
    pub algorithm: Option<String>,
    pub key_name_hint: Option<String>,
    pub value_size: u64,
    pub sign_images: Vec<String>,
    pub hashed_nodes: Vec<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FitControlKey {
    pub fdt_offset: u64,
    pub offset: u64,
    pub node_path: String,
    pub algorithm: Option<String>,
    pub key_name_hint: Option<String>,
    /// Stored `required` property, usually `image` or `conf`; does not establish enforcement.
    pub required: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FitDiagnostic {
    pub offset: u64,
    pub code: String,
    pub message: String,
}
