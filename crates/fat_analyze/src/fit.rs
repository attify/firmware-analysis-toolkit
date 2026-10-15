//! Bounded FIT metadata inspection. No cryptographic verification or boot policy inference.

use std::collections::BTreeSet;

use fat_core::fit::{
    FitBlob, FitConfiguration, FitControlKey, FitDiagnostic, FitHash, FitImage, FitReference,
    FitScanReport, FitSignature,
};
use memchr::memmem;

use crate::firmware_formats::{FdtNode, FdtScanBudget, ValidatedFdt};

const MAX_METADATA_BYTES: usize = 4096;
const MAX_HASH_BYTES: usize = 128;
const REFERENCE_PROPERTIES: &[&str] = &[
    "kernel",
    "fdt",
    "ramdisk",
    "firmware",
    "loadables",
    "script",
    "standalone",
    "setup",
    "fpga",
];

pub fn scan(bytes: &[u8]) -> FitScanReport {
    let mut report = FitScanReport::default();
    let mut budget = FdtScanBudget::default();
    for offset in memmem::find_iter(bytes, &0xd00d_feedu32.to_be_bytes()) {
        match budget.parse(&bytes[offset..], offset as u64) {
            Ok(tree) => {
                let mut reader = Reader {
                    offset: offset as u64,
                    complete: true,
                    diagnostics: &mut report.diagnostics,
                };
                reader.control_keys(&tree, &mut report.control_keys);
                if tree.is_fit() {
                    // Control-key metadata has its own diagnostics and does not affect the FIT tree.
                    reader.complete = true;
                    report.blobs.push(reader.blob(&tree));
                }
            }
            Err(diagnostic) => report.diagnostics.push(diagnostic),
        }
        if budget.exhausted {
            break;
        }
    }
    report
}

fn diagnostic(diagnostics: &mut Vec<FitDiagnostic>, offset: u64, code: &str, message: &str) {
    diagnostics.push(FitDiagnostic {
        offset,
        code: code.to_string(),
        message: message.to_string(),
    });
}

struct Reader<'a> {
    offset: u64,
    complete: bool,
    diagnostics: &'a mut Vec<FitDiagnostic>,
}

impl Reader<'_> {
    fn invalid(&mut self, node: &FdtNode<'_>, message: &str) {
        self.complete = false;
        diagnostic(
            self.diagnostics,
            self.offset + node.offset as u64,
            "FIT-METADATA-INVALID",
            message,
        );
    }

    fn strings(&mut self, node: &FdtNode<'_>, name: &str) -> Option<Vec<String>> {
        let property = node.property(name)?;
        let value = property.value;
        if value.is_empty() || value.len() > MAX_METADATA_BYTES || value.last() != Some(&0) {
            self.complete = false;
            diagnostic(
                self.diagnostics,
                self.offset + property.offset as u64,
                "FIT-METADATA-INVALID",
                &format!("{} property is not a bounded, terminated string list", name),
            );
            return None;
        }
        let result: Option<Vec<_>> = value[..value.len() - 1]
            .split(|&byte| byte == 0)
            .map(|item| {
                std::str::from_utf8(item)
                    .ok()
                    .filter(|text| !text.is_empty() && !text.chars().any(char::is_control))
                    .map(str::to_owned)
            })
            .collect();
        match result {
            Some(items) => Some(items),
            None => {
                self.invalid(
                    node,
                    &format!("{} property contains invalid string metadata", name),
                );
                None
            }
        }
    }

    fn string(&mut self, node: &FdtNode<'_>, name: &str) -> Option<String> {
        let mut items = self.strings(node, name)?;
        if items.len() != 1 {
            self.invalid(node, &format!("{} property must contain one string", name));
            return None;
        }
        items.pop()
    }

    fn blob(&mut self, tree: &ValidatedFdt<'_>) -> FitBlob {
        let images_index = tree.child(0, "images").expect("validated FIT images node");
        let configurations_index = tree.child(0, "configurations");
        let mut blob = FitBlob {
            offset: self.offset,
            size: tree.total_size as u64,
            description: self.string(&tree.nodes[0], "description"),
            default_configuration: configurations_index
                .and_then(|index| self.string(&tree.nodes[index], "default")),
            ..Default::default()
        };
        for &index in &tree.nodes[images_index].children {
            let node = &tree.nodes[index];
            let path = format!("/images/{}", node.name);
            let (hashes, signatures) = self.authentication(tree, index, &path, true);
            blob.images.push(FitImage {
                name: node.name.to_string(),
                node_path: path,
                offset: self.offset + node.offset as u64,
                hashes,
                signatures,
            });
        }
        let image_names: BTreeSet<&str> = blob
            .images
            .iter()
            .map(|image| image.name.as_str())
            .collect();
        for &index in configurations_index
            .map(|index| tree.nodes[index].children.as_slice())
            .unwrap_or_default()
        {
            let node = &tree.nodes[index];
            let path = format!("/configurations/{}", node.name);
            let (hashes, signatures) = self.authentication(tree, index, &path, false);
            let mut references = Vec::new();
            for &property in REFERENCE_PROPERTIES {
                if let Some(images) = self.strings(node, property) {
                    let missing: BTreeSet<&str> = images
                        .iter()
                        .map(String::as_str)
                        .filter(|image| !image_names.contains(image))
                        .collect();
                    for image in missing {
                        self.invalid(
                            node,
                            &format!("{} references missing image {}", property, image),
                        );
                    }
                    references.push(FitReference {
                        property: property.to_string(),
                        images,
                    });
                }
            }
            blob.configurations.push(FitConfiguration {
                name: node.name.to_string(),
                node_path: path,
                offset: self.offset + node.offset as u64,
                references,
                hashes,
                signatures,
            });
        }
        if let Some(default) = &blob.default_configuration {
            if !blob.configurations.iter().any(|item| item.name == *default) {
                self.invalid(
                    &tree.nodes[configurations_index.expect("default has configurations node")],
                    "default references a missing configuration",
                );
            }
        }
        blob.complete = self.complete;
        blob
    }

    fn authentication(
        &mut self,
        tree: &ValidatedFdt<'_>,
        index: usize,
        path: &str,
        require_hash_value: bool,
    ) -> (Vec<FitHash>, Vec<FitSignature>) {
        let mut hashes = Vec::new();
        let mut signatures = Vec::new();
        for &child in &tree.nodes[index].children {
            let node = &tree.nodes[child];
            let node_path = format!("{}/{}", path, node.name);
            if named(node.name, "hash") {
                let algorithm = self.string(node, "algo");
                let value = node.property("value").map(|p| p.value);
                // U-Boot's image-host.c generates values for image hash nodes;
                // configuration processing handles signature nodes only. Preserve
                // configuration hash declarations without inventing a missing digest.
                if algorithm.is_none()
                    || (require_hash_value && value.is_none_or(|value| value.is_empty()))
                {
                    self.invalid(node, "hash node lacks an algorithm or hash value");
                }
                if let Some(algorithm) = algorithm.as_deref() {
                    let expected_size = match algorithm {
                        "crc32" => Some(4),
                        "md5" => Some(16),
                        "sha1" => Some(20),
                        "sha256" => Some(32),
                        "sha384" => Some(48),
                        "sha512" => Some(64),
                        _ => None,
                    };
                    match expected_size {
                        Some(expected) if value.is_some_and(|value| value.len() != expected) => {
                            self.invalid(
                                node,
                                &format!(
                                    "{} hash value must contain {} bytes",
                                    algorithm, expected
                                ),
                            );
                        }
                        None => {
                            self.invalid(node, &format!("unsupported hash algorithm {}", algorithm))
                        }
                        _ => {}
                    }
                }
                let value_truncated = value.is_some_and(|value| value.len() > MAX_HASH_BYTES);
                if value_truncated {
                    self.invalid(node, "hash value exceeds the metadata byte budget");
                }
                hashes.push(FitHash {
                    node_path,
                    offset: self.offset + node.offset as u64,
                    algorithm,
                    value_hex: value.map(|value| {
                        value
                            .iter()
                            .take(MAX_HASH_BYTES)
                            .map(|byte| format!("{:02x}", byte))
                            .collect()
                    }),
                    value_size: value.map_or(0, |value| value.len() as u64),
                    value_truncated,
                });
            } else if named(node.name, "signature") {
                let algorithm = self.string(node, "algo");
                let value_size = node.property("value").map_or(0, |p| p.value.len() as u64);
                if algorithm.is_none() || value_size == 0 {
                    self.invalid(node, "signature node lacks an algorithm or signature value");
                }
                signatures.push(FitSignature {
                    node_path,
                    offset: self.offset + node.offset as u64,
                    algorithm,
                    key_name_hint: self.string(node, "key-name-hint"),
                    value_size,
                    sign_images: self.strings(node, "sign-images").unwrap_or_default(),
                    hashed_nodes: self.strings(node, "hashed-nodes").unwrap_or_default(),
                });
            }
        }
        (hashes, signatures)
    }

    fn control_keys(&mut self, tree: &ValidatedFdt<'_>, keys: &mut Vec<FitControlKey>) {
        let Some(signature) = tree.child(0, "signature") else {
            return;
        };
        for &index in &tree.nodes[signature].children {
            let node = &tree.nodes[index];
            keys.push(FitControlKey {
                fdt_offset: self.offset,
                offset: self.offset + node.offset as u64,
                node_path: format!("/signature/{}", node.name),
                algorithm: self.string(node, "algo"),
                key_name_hint: self.string(node, "key-name-hint"),
                required: self.string(node, "required"),
            });
        }
    }
}

fn named(name: &str, prefix: &str) -> bool {
    // U-Boot recognizes hash/signature subnodes by prefix, including vendor suffixes.
    // boot/image-fit-sig.c: fit_image_verify_sig and fit_config_verify_key.
    name.starts_with(prefix)
}
