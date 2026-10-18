//! Assemble reusable firmware analyses into a BMC-focused static inspection.
use crate::{
    boot_env::{self, EnvScanOptions},
    bootloader,
};
use fat_core::bmc::{BmcFinding, BmcIdentityEvidence, BmcInspectionReport, LocatedMarker};
use memchr::memmem;
use sha2::{Digest, Sha256};

const MAX_MARKER_HITS: usize = 32;

#[derive(Debug, Clone, Default)]
pub struct BmcOptions {
    pub environment: EnvScanOptions,
}

pub fn inspect_bytes(
    bytes: &[u8],
    artifact_path: &str,
    options: &BmcOptions,
) -> Result<BmcInspectionReport, String> {
    let snapshot = bootloader::analyze_firmware_bytes(bytes).map_err(|e| e.to_string())?;
    let layout =
        bootloader::build_layout_report_with_bytes(&snapshot, bytes).map_err(|e| e.to_string())?;
    let environment_scan = boot_env::scan(bytes, &options.environment)?;
    let mut report = BmcInspectionReport {
        schema_version: "bmc-inspection/v1".into(),
        artifact_path: artifact_path.into(),
        image_size: bytes.len() as u64,
        sha256: format!("{:x}", Sha256::digest(bytes)),
        identity: Vec::new(),
        bootloader_versions: Vec::new(),
        layout,
        fit: snapshot.fit,
        environment_scan,
        trust_markers: Vec::new(),
        findings: Vec::new(),
        diagnostics: Vec::new(),
    };
    for (needle, category, value) in [
        ("OpenBMC", "firmware-stack-marker", "OpenBMC"),
        ("openbmc", "firmware-stack-marker", "OpenBMC"),
        ("MegaRAC", "firmware-stack-marker", "AMI MegaRAC"),
        ("aspeed,ast2400", "compatible-string", "ASPEED AST2400"),
        ("aspeed,ast2500", "compatible-string", "ASPEED AST2500"),
        ("aspeed,ast2600", "compatible-string", "ASPEED AST2600"),
        ("aspeed,ast2700", "compatible-string", "ASPEED AST2700"),
    ] {
        if let Some(offset) = memmem::find(bytes, needle.as_bytes()) {
            if !report
                .identity
                .iter()
                .any(|e| e.category == category && e.value == value)
            {
                report.identity.push(BmcIdentityEvidence {
                    category: category.into(),
                    value: value.into(),
                    offset: offset as u64,
                    evidence: context(bytes, offset),
                });
            }
        }
    }
    for offset in memmem::find_iter(bytes, b"U-Boot ")
        .filter(|offset| bytes.get(offset + 7).is_some_and(u8::is_ascii_digit))
        .take(8)
    {
        report.bootloader_versions.push(LocatedMarker {
            kind: "version-string".into(),
            name: "U-Boot".into(),
            offset: offset as u64,
            length: 7,
            context: context(bytes, offset),
        });
    }
    for (needle, kind) in [
        ("fwmap", "update-metadata-name"),
        ("sig_table", "signature-table-name"),
        ("AdaptiveModules", "AMI-module-marker"),
        ("verify_image", "verification-name"),
        ("SecureBoot", "verification-name"),
        ("BootVerify", "verification-name"),
        ("VerifyFW", "verification-name"),
        ("-----BEGIN RSA PRIVATE KEY-----", "private-key-header"),
        ("-----BEGIN EC PRIVATE KEY-----", "private-key-header"),
        ("-----BEGIN PRIVATE KEY-----", "private-key-header"),
        ("-----BEGIN CERTIFICATE-----", "public-key-header"),
        ("-----BEGIN PUBLIC KEY-----", "public-key-header"),
    ] {
        let mut offsets = memmem::find_iter(bytes, needle.as_bytes());
        for offset in offsets.by_ref().take(MAX_MARKER_HITS) {
            let (rule, level, message) = match kind {
                "private-key-header" => (
                    "BMC-PRIVATE-KEY-MARKER",
                    "warning",
                    format!("Private-key PEM header {needle} occurs in raw firmware"),
                ),
                "public-key-header" => (
                    "BMC-PUBLIC-KEY-MARKER",
                    "note",
                    format!("Public-key/certificate PEM header {needle} occurs in raw firmware"),
                ),
                _ => (
                    "BMC-TRUST-MARKER",
                    "note",
                    format!("Located {kind}: {needle}"),
                ),
            };
            report.trust_markers.push(LocatedMarker {
                kind: kind.into(),
                name: needle.into(),
                offset: offset as u64,
                length: needle.len() as u64,
                context: context(bytes, offset),
            });
            report.findings.push(finding(
                rule,
                level,
                message,
                offset as u64,
                needle.len() as u64,
                None,
            ));
        }
        if offsets.next().is_some() {
            report.diagnostics.push(format!(
                "Marker {needle}: showing first {MAX_MARKER_HITS} occurrences"
            ));
        }
    }
    for blob in &report.fit.blobs {
        if !blob.complete {
            continue;
        }
        let signatures = blob
            .images
            .iter()
            .map(|i| i.signatures.len())
            .sum::<usize>()
            + blob
                .configurations
                .iter()
                .map(|c| c.signatures.len())
                .sum::<usize>();
        if signatures > 0 {
            report.findings.push(finding("BOOT-FIT-SIGNATURE-METADATA", "note",
                format!("FIT contains {signatures} signature metadata node(s); cryptographic validity and bootloader enforcement are untested"), blob.offset, 4, Some("/".into())));
        } else if !blob.images.is_empty() && blob.images.iter().all(|i| !i.hashes.is_empty()) {
            report.findings.push(finding(
                "BOOT-FIT-HASH-ONLY",
                "warning",
                "FIT contains image hash metadata and no image or configuration signature nodes"
                    .into(),
                blob.offset,
                4,
                Some("/".into()),
            ));
        }
    }
    for env in &report.environment_scan.environments {
        for var in &env.variables {
            if matches!(var.key.as_str(), "verify" | "sig_check")
                && matches!(
                    var.value.trim().to_ascii_lowercase().as_str(),
                    "0" | "no" | "n" | "false" | "off" | "disabled"
                )
            {
                report.findings.push(finding("BOOT-ENV-CHECK-DISABLED", "warning",
                    format!("CRC-valid stored environment sets {}={}; active environment selection is unresolved", var.key, var.value),
                    var.offset, (var.key.len() + var.value.len() + 1) as u64, None));
            }
        }
    }
    report
        .findings
        .sort_by(|a, b| (a.offset, &a.rule_id).cmp(&(b.offset, &b.rule_id)));
    Ok(report)
}

fn finding(
    rule: &str,
    level: &str,
    message: String,
    offset: u64,
    length: u64,
    node_path: Option<String>,
) -> BmcFinding {
    BmcFinding {
        rule_id: rule.into(),
        level: level.into(),
        message,
        offset,
        length,
        node_path,
    }
}

fn context(bytes: &[u8], offset: usize) -> String {
    bytes[offset..]
        .iter()
        .take(160)
        .take_while(|b| b.is_ascii_graphic() || **b == b' ')
        .map(|b| char::from(*b))
        .collect()
}
