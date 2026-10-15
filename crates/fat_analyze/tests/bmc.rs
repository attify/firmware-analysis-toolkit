use fat_analyze::bmc::{inspect_bytes, BmcOptions};

#[test]
fn preserves_input_hash_and_located_bmc_evidence_without_claiming_vulnerability() {
    let bytes = b"prefix OpenBMC build\0aspeed,ast2500\0fwmap\0sig_table\0AdaptiveModules\0";
    let report = inspect_bytes(bytes, "fixture.mtd", &BmcOptions::default()).unwrap();
    assert_eq!(report.schema_version, "bmc-inspection/v1");
    assert_eq!(report.image_size, bytes.len() as u64);
    assert_eq!(report.sha256.len(), 64);
    assert!(report
        .identity
        .iter()
        .any(|e| e.value == "OpenBMC" && e.offset == 7));
    assert_eq!(report.trust_markers.len(), 3);
    assert!(report.findings.iter().all(|f| f.level == "note"));
    assert!(!report.identity.iter().any(|e| e.value == "AMI MegaRAC"));
}

#[test]
fn empty_or_arbitrary_data_does_not_imply_a_bmc_or_missing_secure_boot() {
    for bytes in [&b""[..], &b"ordinary firmware unrelated to BMC"[..]] {
        let report = inspect_bytes(bytes, "sample.bin", &BmcOptions::default()).unwrap();
        assert!(report.identity.is_empty());
        assert!(report.findings.is_empty());
        assert!(report.fit.blobs.is_empty());
    }
}

#[test]
fn public_certificate_marker_is_informational_and_private_marker_is_qualified() {
    let bytes = b"-----BEGIN CERTIFICATE-----\0-----BEGIN PRIVATE KEY-----\0";
    let report = inspect_bytes(bytes, "keys.bin", &BmcOptions::default()).unwrap();
    assert!(report
        .findings
        .iter()
        .any(|f| f.rule_id == "BMC-PUBLIC-KEY-MARKER" && f.level == "note"));
    assert!(report
        .findings
        .iter()
        .any(|f| f.rule_id == "BMC-PRIVATE-KEY-MARKER"
            && f.level == "warning"
            && f.message.contains("header")));
}

#[test]
fn fit_descriptions_are_not_reported_as_bootloader_version_strings() {
    let bytes = b"U-Boot fitImage for OpenBMC\0U-Boot 2016.07 (Jan 08 2021)\0";
    let report = inspect_bytes(bytes, "flash.mtd", &BmcOptions::default()).unwrap();
    assert_eq!(report.bootloader_versions.len(), 1);
    assert!(report.bootloader_versions[0]
        .context
        .starts_with("U-Boot 2016.07"));
}
