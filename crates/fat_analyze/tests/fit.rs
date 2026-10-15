use fat_analyze::fit::scan;

#[derive(Default)]
struct Fdt {
    structure: Vec<u8>,
    strings: Vec<u8>,
}
impl Fdt {
    fn word(&mut self, word: u32) {
        self.structure.extend(word.to_be_bytes());
    }
    fn pad(&mut self) {
        while !self.structure.len().is_multiple_of(4) {
            self.structure.push(0);
        }
    }
    fn begin(&mut self, name: &str) {
        self.word(1);
        self.structure.extend(name.as_bytes());
        self.structure.push(0);
        self.pad();
    }
    fn end(&mut self) {
        self.word(2);
    }
    fn property(&mut self, name: &str, value: &[u8]) {
        self.word(3);
        self.word(value.len() as u32);
        self.word(self.strings.len() as u32);
        self.strings.extend(name.as_bytes());
        self.strings.push(0);
        self.structure.extend(value);
        self.pad();
    }
    fn text(&mut self, name: &str, value: &str) {
        let mut bytes = value.as_bytes().to_vec();
        bytes.push(0);
        self.property(name, &bytes);
    }
    fn finish(mut self) -> Vec<u8> {
        self.word(9);
        let strings_offset = 56 + self.structure.len();
        let size = strings_offset + self.strings.len();
        let mut bytes = Vec::new();
        for word in [
            0xd00dfeed,
            size as u32,
            56,
            strings_offset as u32,
            40,
            17,
            16,
            0,
            self.strings.len() as u32,
            self.structure.len() as u32,
        ] {
            bytes.extend(word.to_be_bytes());
        }
        bytes.extend([0; 16]);
        bytes.extend(self.structure);
        bytes.extend(self.strings);
        bytes
    }
}
fn fixture(image_signature: bool, configuration_signature: bool) -> Vec<u8> {
    let mut f = Fdt::default();
    f.begin("");
    f.text("description", "test FIT");
    f.begin("images");
    f.begin("kernel-1");
    f.property("data", &[0x41; 16]);
    f.begin("hash@1");
    f.text("algo", "sha256");
    f.property("value", &[0xab; 32]);
    f.end();
    if image_signature {
        f.begin("signature@1");
        f.text("algo", "sha256,rsa2048");
        f.text("key-name-hint", "dev");
        f.property("value", &[0x12; 256]);
        f.end();
    }
    f.end();
    f.begin("fdt-1");
    f.end();
    f.end();
    f.begin("configurations");
    f.text("default", "conf-1");
    f.begin("conf-1");
    f.text("kernel", "kernel-1");
    f.text("fdt", "fdt-1");
    if configuration_signature {
        f.begin("signature-1");
        f.text("algo", "sha256,rsa2048");
        f.text("key-name-hint", "production");
        f.property("sign-images", b"kernel\0fdt\0");
        f.property("hashed-nodes", b"/\0/images/kernel-1\0");
        f.property("value", &[0x34; 256]);
        f.end();
    }
    f.end();
    f.end();
    f.end();
    f.finish()
}

#[test]
fn preserves_hash_metadata_and_embedded_offsets() {
    let fit = fixture(false, false);
    let mut bytes = vec![0xff; 511];
    bytes.extend(&fit);
    let report = scan(&bytes);
    assert!(report.diagnostics.is_empty());
    assert_eq!(report.blobs.len(), 1);
    let blob = &report.blobs[0];
    assert_eq!(blob.offset, 511);
    assert_eq!(blob.size, fit.len() as u64);
    assert!(blob.complete);
    assert_eq!(blob.description.as_deref(), Some("test FIT"));
    assert_eq!(blob.default_configuration.as_deref(), Some("conf-1"));
    let image = &blob.images[0];
    assert_eq!(image.node_path, "/images/kernel-1");
    assert!(image.offset > 511);
    assert!(image.signatures.is_empty());
    assert_eq!(image.hashes[0].algorithm.as_deref(), Some("sha256"));
    assert_eq!(image.hashes[0].value_hex, Some("ab".repeat(32)));
    assert!(!image.hashes[0].value_truncated);
}

#[test]
fn distinguishes_individual_image_and_configuration_signatures() {
    let report = scan(&fixture(true, true));
    assert_eq!(report.blobs.len(), 1);
    let blob = &report.blobs[0];
    assert!(blob.complete);
    assert_eq!(blob.images[0].signatures[0].value_size, 256);
    assert_eq!(
        blob.images[0].signatures[0].key_name_hint.as_deref(),
        Some("dev")
    );
    let conf = &blob.configurations[0];
    assert_eq!(
        conf.signatures[0].node_path,
        "/configurations/conf-1/signature-1"
    );
    assert_eq!(conf.signatures[0].sign_images, vec!["kernel", "fdt"]);
    assert_eq!(
        conf.signatures[0].hashed_nodes,
        vec!["/", "/images/kernel-1"]
    );
    assert_eq!(conf.references[0].images, vec!["kernel-1"]);
}

#[test]
fn configuration_signature_is_preserved_with_unsigned_image_nodes() {
    let report = scan(&fixture(false, true));
    assert_eq!(report.blobs.len(), 1);
    let blob = &report.blobs[0];
    assert!(blob.images.iter().all(|image| image.signatures.is_empty()));
    assert_eq!(blob.configurations[0].signatures.len(), 1);
}

#[test]
fn preserves_multiple_configuration_references() {
    let mut f = Fdt::default();
    f.begin("");
    f.begin("images");
    for name in ["kernel-a", "kernel-b", "fdt-a"] {
        f.begin(name);
        f.end();
    }
    f.end();
    f.begin("configurations");
    f.text("default", "conf-b");
    for (name, reference) in [("conf-a", "kernel-a"), ("conf-b", "kernel-b")] {
        f.begin(name);
        f.text("kernel", reference);
        f.property("loadables", b"kernel-a\0fdt-a\0");
        f.end();
    }
    f.end();
    f.end();
    let report = scan(&f.finish());
    assert_eq!(report.blobs.len(), 1);
    let blob = &report.blobs[0];
    assert_eq!(blob.default_configuration.as_deref(), Some("conf-b"));
    assert_eq!(blob.configurations.len(), 2);
    assert_eq!(
        blob.configurations[1].references[1].images,
        vec!["kernel-a", "fdt-a"]
    );
}

#[test]
fn reports_required_control_key_metadata_without_a_fit() {
    let mut f = Fdt::default();
    f.begin("");
    f.begin("signature");
    f.begin("key-production");
    f.text("algo", "sha256,rsa2048");
    f.text("key-name-hint", "production");
    f.text("required", "conf");
    f.property("rsa,modulus", &[0x51; 256]);
    f.end();
    f.end();
    f.end();
    let mut bytes = vec![0; 128];
    bytes.extend(f.finish());
    let report = scan(&bytes);
    assert!(report.blobs.is_empty());
    assert_eq!(report.control_keys.len(), 1);
    let key = &report.control_keys[0];
    assert_eq!(key.fdt_offset, 128);
    assert_eq!(key.node_path, "/signature/key-production");
    assert_eq!(key.required.as_deref(), Some("conf"));
}

#[test]
fn malformed_fdt_candidates_leave_diagnostics() {
    let fit = fixture(false, false);
    let mut bad_offset = fit.clone();
    bad_offset[8..12].copy_from_slice(&u32::MAX.to_be_bytes());
    let mut bad_length = fit.clone();
    bad_length[36..40].copy_from_slice(&u32::MAX.to_be_bytes());
    for bytes in [bad_offset, bad_length, fit[..fit.len() - 1].to_vec()] {
        let report = scan(&bytes);
        assert!(report.blobs.is_empty());
        assert!(!report.diagnostics.is_empty());
    }
}

#[test]
fn rejects_ambiguous_duplicate_nodes_and_properties() {
    let mut duplicate_nodes = Fdt::default();
    duplicate_nodes.begin("");
    for _ in 0..2 {
        duplicate_nodes.begin("images");
        duplicate_nodes.end();
    }
    duplicate_nodes.begin("configurations");
    duplicate_nodes.end();
    duplicate_nodes.end();
    let mut duplicate_props = Fdt::default();
    duplicate_props.begin("");
    duplicate_props.text("description", "a");
    duplicate_props.text("description", "b");
    duplicate_props.end();
    for bytes in [duplicate_nodes.finish(), duplicate_props.finish()] {
        let report = scan(&bytes);
        assert!(report.blobs.is_empty());
        assert!(!report.diagnostics.is_empty());
    }
}

#[test]
fn malformed_semantic_property_retains_blob_without_absence_conclusions() {
    let mut f = Fdt::default();
    f.begin("");
    f.begin("images");
    f.begin("kernel");
    f.begin("hash-1");
    f.property("algo", b"sha256");
    f.end();
    f.end();
    f.end();
    f.begin("configurations");
    f.begin("default");
    f.text("kernel", "missing-image");
    f.end();
    f.end();
    f.end();
    let report = scan(&f.finish());
    assert_eq!(report.blobs.len(), 1);
    assert!(!report.blobs[0].complete);
    assert!(!report.diagnostics.is_empty());
}

#[test]
fn invalid_names_and_depth_exhaustion_leave_diagnostics() {
    for invalid_name in ["a/b", "\u{7f}"] {
        let mut f = Fdt::default();
        f.begin("");
        f.begin(invalid_name);
        f.end();
        f.end();
        let report = scan(&f.finish());
        assert!(report.blobs.is_empty());
        assert!(!report.diagnostics.is_empty());
    }
    let mut f = Fdt::default();
    f.begin("");
    for _ in 0..257 {
        f.begin("n");
    }
    for _ in 0..258 {
        f.end();
    }
    let report = scan(&f.finish());
    assert!(!report.diagnostics.is_empty());
    assert!(report.blobs.is_empty());
}

#[test]
fn scans_multiple_fit_blobs() {
    let mut bytes = fixture(false, false);
    bytes.extend([0xff; 17]);
    bytes.extend(fixture(false, true));
    assert_eq!(scan(&bytes).blobs.len(), 2);
}

#[test]
fn reports_fit_images_without_optional_configurations() {
    let mut f = Fdt::default();
    f.begin("");
    f.begin("images");
    f.begin("kernel");
    f.begin("hash-1");
    f.text("algo", "sha256");
    f.property("value", &[0xab; 32]);
    f.end();
    f.end();
    f.end();
    f.end();
    let report = scan(&f.finish());
    assert_eq!(report.blobs.len(), 1);
    assert!(report.blobs[0].complete);
    assert!(report.blobs[0].configurations.is_empty());
}

#[test]
fn bounds_hash_values_and_marks_metadata_incomplete() {
    let mut f = Fdt::default();
    f.begin("");
    f.begin("images");
    f.begin("kernel");
    f.begin("hash-1");
    f.text("algo", "sha256");
    f.property("value", &[0xab; 8192]);
    f.end();
    f.end();
    f.end();
    f.begin("configurations");
    f.end();
    f.end();
    let report = scan(&f.finish());
    assert_eq!(report.blobs.len(), 1);
    let blob = &report.blobs[0];
    assert!(!blob.complete);
    assert!(blob.images[0].hashes[0].value_truncated);
    assert_eq!(blob.images[0].hashes[0].value_size, 8192);
    assert_eq!(
        blob.images[0].hashes[0].value_hex.as_ref().unwrap().len(),
        256
    );
}

#[test]
fn scan_candidate_budget_emits_explicit_limit() {
    let bytes = 0xd00dfeedu32.to_be_bytes().repeat(1100);
    let report = scan(&bytes);
    assert!(report.blobs.is_empty());
    assert_eq!(report.diagnostics.last().unwrap().code, "FDT-SCAN-LIMIT");
}

#[test]
fn node_budget_emits_explicit_limit() {
    let mut f = Fdt::default();
    f.begin("");
    for i in 0..16_384 {
        f.begin(&format!("n{}", i));
        f.end();
    }
    f.end();
    let report = scan(&f.finish());
    assert!(report.blobs.is_empty());
    assert_eq!(report.diagnostics[0].code, "FDT-PARSE-LIMIT");
}

#[test]
fn snapshot_integration_merges_without_duplicate_evidence() {
    let snapshot = fat_analyze::bootloader::analyze_firmware_bytes(&fixture(false, true)).unwrap();
    assert_eq!(snapshot.fit.blobs.len(), 1);
    let merged = fat_analyze::bootloader::merge_snapshots(snapshot.clone(), snapshot);
    assert_eq!(merged.fit.blobs.len(), 1);
}

#[test]
fn old_snapshot_json_without_fit_remains_readable() {
    let mut value =
        serde_json::to_value(fat_core::bootloader::BootloaderSnapshot::default()).unwrap();
    value.as_object_mut().unwrap().remove("fit");
    let snapshot: fat_core::bootloader::BootloaderSnapshot = serde_json::from_value(value).unwrap();
    assert!(snapshot.fit.blobs.is_empty());
}

#[test]
fn malformed_declared_size_does_not_hide_a_later_fit() {
    let mut bytes = vec![0; 40];
    bytes[..4].copy_from_slice(&0xd00dfeedu32.to_be_bytes());
    bytes[36..40].copy_from_slice(&u32::MAX.to_be_bytes());
    bytes.extend(fixture(false, false));
    let report = scan(&bytes);
    assert_eq!(report.blobs.len(), 1);
    assert_eq!(report.blobs[0].offset, 40);
    assert_eq!(report.diagnostics[0].code, "FDT-INVALID");
    let native = fat_analyze::firmware_formats::scan(&bytes);
    assert_eq!(native.container_headers.len(), 1);
    assert_eq!(native.container_headers[0].offset, 40);
    assert_eq!(native.fdt_diagnostics, report.diagnostics);
}

#[test]
fn preserves_signature_nodes_with_uboot_prefix_matching() {
    let mut f = Fdt::default();
    f.begin("");
    f.begin("images");
    f.begin("kernel");
    f.begin("signature_vendor");
    f.text("algo", "sha256,rsa2048");
    f.property("value", &[0xab; 256]);
    f.end();
    f.end();
    f.end();
    f.begin("configurations");
    f.end();
    f.end();
    let report = scan(&f.finish());
    assert_eq!(report.blobs[0].images[0].signatures.len(), 1);
}

#[test]
fn inconsistent_or_unsupported_hash_algorithms_are_incomplete() {
    for (algorithm, value) in [
        ("sha256", vec![0xab; 1]),
        ("sha256", vec![0xab; 33]),
        ("vendor-hash", vec![0xab; 32]),
    ] {
        let mut f = Fdt::default();
        f.begin("");
        f.begin("images");
        f.begin("kernel");
        f.begin("hash-1");
        f.text("algo", algorithm);
        f.property("value", &value);
        f.end();
        f.end();
        f.end();
        f.begin("configurations");
        f.end();
        f.end();
        let report = scan(&f.finish());
        let blob = &report.blobs[0];
        assert!(
            !blob.complete,
            "algorithm={algorithm}, value length={}",
            value.len()
        );
        assert_eq!(
            blob.images[0].hashes[0].algorithm.as_deref(),
            Some(algorithm)
        );
        assert_eq!(blob.images[0].hashes[0].value_size, value.len() as u64);
        assert!(report
            .diagnostics
            .iter()
            .any(|diagnostic| diagnostic.code == "FIT-METADATA-INVALID"));
    }
}

#[test]
fn supported_hash_algorithms_require_their_declared_digest_lengths() {
    for (algorithm, length) in [
        ("crc32", 4),
        ("md5", 16),
        ("sha1", 20),
        ("sha256", 32),
        ("sha384", 48),
        ("sha512", 64),
    ] {
        let mut f = Fdt::default();
        f.begin("");
        f.begin("images");
        f.begin("kernel");
        f.begin("hash-1");
        f.text("algo", algorithm);
        f.property("value", &vec![0xab; length]);
        f.end();
        f.end();
        f.end();
        f.begin("configurations");
        f.end();
        f.end();
        let report = scan(&f.finish());
        assert!(report.blobs[0].complete, "algorithm={algorithm}");
        assert!(report.diagnostics.is_empty());
    }
}

#[test]
fn configuration_hash_algorithm_declaration_does_not_require_a_digest() {
    let mut f = Fdt::default();
    f.begin("");
    f.begin("images");
    f.begin("kernel");
    f.begin("hash@1");
    f.text("algo", "sha256");
    f.property("value", &[0xab; 32]);
    f.end();
    f.end();
    f.end();
    f.begin("configurations");
    f.text("default", "conf@board.dtb");
    f.begin("conf@board.dtb");
    f.text("kernel", "kernel");
    f.begin("hash@1");
    f.text("algo", "sha256");
    f.end();
    f.end();
    f.end();
    f.end();
    let report = scan(&f.finish());
    let blob = &report.blobs[0];
    assert!(blob.complete);
    assert!(report.diagnostics.is_empty());
    let declaration = &blob.configurations[0].hashes[0];
    assert_eq!(declaration.algorithm.as_deref(), Some("sha256"));
    assert_eq!(declaration.value_size, 0);
    assert_eq!(declaration.value_hex, None);
}

#[test]
fn image_hash_declaration_without_value_remains_incomplete() {
    let mut f = Fdt::default();
    f.begin("");
    f.begin("images");
    f.begin("kernel");
    f.begin("hash-1");
    f.text("algo", "sha256");
    f.end();
    f.end();
    f.end();
    f.end();
    let report = scan(&f.finish());
    assert!(!report.blobs[0].complete);
    assert!(!report.diagnostics.is_empty());
}

#[test]
fn configuration_hash_declarations_reject_unknown_algorithms_and_wrong_values() {
    for (algorithm, value) in [
        ("unknown", None),
        ("sha256", Some(&b"x"[..])),
        ("sha256", Some(&b""[..])),
    ] {
        let mut f = Fdt::default();
        f.begin("");
        f.begin("images");
        f.begin("kernel");
        f.end();
        f.end();
        f.begin("configurations");
        f.begin("conf");
        f.begin("hash-1");
        f.text("algo", algorithm);
        if let Some(value) = value {
            f.property("value", value);
        }
        f.end();
        f.end();
        f.end();
        f.end();
        let report = scan(&f.finish());
        assert!(!report.blobs[0].complete);
        assert!(!report.diagnostics.is_empty());
    }
}

#[test]
fn repeated_missing_references_preserve_values_without_duplicate_diagnostics() {
    let mut f = Fdt::default();
    f.begin("");
    f.begin("images");
    f.begin("kernel");
    f.end();
    f.end();
    f.begin("configurations");
    f.begin("conf");
    f.property("loadables", b"x\0x\0kernel\0y\0x\0y\0");
    f.end();
    f.end();
    f.end();
    let report = scan(&f.finish());
    assert_eq!(report.diagnostics.len(), 2);
    assert!(!report.blobs[0].complete);
    assert_eq!(
        report.blobs[0].configurations[0].references[0].images,
        ["x", "x", "kernel", "y", "x", "y"]
    );
}

#[test]
fn native_scanner_caps_fdt_candidates() {
    let mut f = Fdt::default();
    f.begin("");
    f.end();
    let bytes = f.finish().repeat(1100);
    let native = fat_analyze::firmware_formats::scan(&bytes);
    assert_eq!(native.container_headers.len(), 1024);
    assert_eq!(native.fdt_diagnostics.len(), 1);
    assert_eq!(native.fdt_diagnostics[0].code, "FDT-SCAN-LIMIT");
    assert_eq!(scan(&bytes).diagnostics, native.fdt_diagnostics);
    let snapshot = fat_analyze::bootloader::analyze_firmware_bytes(&bytes).unwrap();
    assert_eq!(snapshot.fit.diagnostics, native.fdt_diagnostics);
}

#[test]
fn native_scanner_caps_cumulative_shared_fdt_structure() {
    // Multiple headers point at one payload; file size alone does not bound parse work.
    let mut f = Fdt::default();
    f.begin("");
    f.property("payload", &vec![0xff; 1024 * 1024]);
    f.end();
    let tree = f.finish();
    let header_count = 300usize;
    let header_area = header_count * 64;
    let mut bytes = vec![0; header_area];
    bytes.extend_from_slice(&tree[56..]);
    for index in 0..header_count {
        let offset = index * 64;
        let structure_offset = header_area - offset;
        let structure_size = u32::from_be_bytes(tree[36..40].try_into().unwrap()) as usize;
        let strings_offset = structure_offset + structure_size;
        let total_size = bytes.len() - offset;
        bytes[offset..offset + 40].copy_from_slice(&tree[..40]);
        bytes[offset + 4..offset + 8].copy_from_slice(&(total_size as u32).to_be_bytes());
        bytes[offset + 8..offset + 12].copy_from_slice(&(structure_offset as u32).to_be_bytes());
        bytes[offset + 12..offset + 16].copy_from_slice(&(strings_offset as u32).to_be_bytes());
    }
    let native = fat_analyze::firmware_formats::scan(&bytes);
    assert_eq!(native.container_headers.len(), 255);
    assert_eq!(native.fdt_diagnostics.len(), 1);
    assert_eq!(native.fdt_diagnostics[0].code, "FDT-SCAN-LIMIT");
    assert!(native.fdt_diagnostics[0]
        .message
        .contains("cumulative structure"));
    assert_eq!(scan(&bytes).diagnostics, native.fdt_diagnostics);
}
