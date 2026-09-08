// Binary diff tests -- TDD: written before implementation.
//
// These tests exercise the matching algorithm and classification logic
// without requiring r2 to be installed. The r2 invocation tests verify
// graceful error handling when r2 is missing.

use fat_analyze::binary_diff;
use fat_analyze::binary_diff::types::{
    FunctionMatch, ImportExportDiff, R2Function, R2String, StringDiff, StringEntry,
};
use fat_analyze::string_diff::{classify_string, diff_classified_strings};

fn empty_ie_diff() -> ImportExportDiff {
    ImportExportDiff {
        added_imports: vec![],
        removed_imports: vec![],
        added_exports: vec![],
        removed_exports: vec![],
    }
}

// ====================================================================
// String classification tests
// ====================================================================

#[test]
fn classify_string_detects_dangerous_calls() {
    assert_eq!(classify_string("system"), Some("DANGEROUS_CALL"));
    assert_eq!(classify_string("popen"), Some("DANGEROUS_CALL"));
    assert_eq!(classify_string("execve"), Some("DANGEROUS_CALL"));
}

#[test]
fn classify_string_detects_credentials() {
    assert_eq!(classify_string("password"), Some("CREDENTIAL"));
    assert_eq!(classify_string("admin"), Some("CREDENTIAL"));
    assert_eq!(classify_string("secret_key"), Some("CREDENTIAL"));
}

#[test]
fn classify_string_detects_endpoints() {
    assert_eq!(classify_string("/cgi-bin/setup"), Some("ENDPOINT"));
    assert_eq!(classify_string("/setform/"), Some("ENDPOINT"));
    assert_eq!(classify_string("/stream/video"), Some("ENDPOINT"));
}

#[test]
fn classify_string_detects_crypto() {
    assert_eq!(classify_string("md5"), Some("CRYPTO"));
    assert_eq!(classify_string("sha256"), Some("CRYPTO"));
    assert_eq!(classify_string("aes_encrypt"), Some("CRYPTO"));
    assert_eq!(classify_string("rsa_key"), Some("CRYPTO"));
    assert_eq!(classify_string("certificate"), Some("CRYPTO"));
}

#[test]
fn classify_string_detects_debug() {
    assert_eq!(classify_string("debug_mode"), Some("DEBUG"));
    assert_eq!(classify_string("dbg_output"), Some("DEBUG"));
    assert_eq!(classify_string("test_flag"), Some("DEBUG"));
}

#[test]
fn classify_string_detects_network() {
    assert_eq!(classify_string("http://example.com"), Some("NETWORK"));
    assert_eq!(classify_string("https://api.local"), Some("NETWORK"));
    assert_eq!(classify_string("socket_init"), Some("NETWORK"));
    assert_eq!(classify_string("bind_port"), Some("NETWORK"));
}

#[test]
fn classify_string_returns_none_for_non_security() {
    assert_eq!(classify_string("hello world"), None);
    assert_eq!(classify_string("version 1.0"), None);
    assert_eq!(classify_string("menu_item"), None);
}

// ====================================================================
// Classified string diff tests
// ====================================================================

#[test]
fn string_diff_detects_new_system_call_as_dangerous() {
    let base = vec!["printf".to_string(), "strlen".to_string()];
    let head = vec![
        "printf".to_string(),
        "strlen".to_string(),
        "system".to_string(),
    ];

    let diff = diff_classified_strings(&base, &head);

    assert_eq!(diff.added.len(), 1);
    assert_eq!(diff.added[0].value, "system");
    assert_eq!(diff.added[0].tag, Some("DANGEROUS_CALL".to_string()));
    assert!(diff.removed.is_empty());
}

#[test]
fn string_diff_detects_removed_cgi_endpoint() {
    let base = vec!["/cgi-bin/admin".to_string(), "/stream/video".to_string()];
    let head = vec!["/stream/video".to_string()];

    let diff = diff_classified_strings(&base, &head);

    assert!(diff.added.is_empty());
    assert_eq!(diff.removed.len(), 1);
    assert_eq!(diff.removed[0].value, "/cgi-bin/admin");
    assert_eq!(diff.removed[0].tag, Some("ENDPOINT".to_string()));
}

#[test]
fn string_diff_handles_identical_sets() {
    let base = vec!["foo".to_string(), "bar".to_string()];
    let head = vec!["foo".to_string(), "bar".to_string()];

    let diff = diff_classified_strings(&base, &head);

    assert!(diff.added.is_empty());
    assert!(diff.removed.is_empty());
}

#[test]
fn string_diff_handles_empty_inputs() {
    let diff = diff_classified_strings(&[], &[]);
    assert!(diff.added.is_empty());
    assert!(diff.removed.is_empty());
}

// ====================================================================
// Function matching tests
// ====================================================================

#[test]
fn function_matching_by_name_is_exact() {
    let base = vec![
        R2Function {
            name: "main".to_string(),
            addr: 0x1000,
            size: 200,
            ninstrs: 50,
        },
        R2Function {
            name: "handle_request".to_string(),
            addr: 0x2000,
            size: 400,
            ninstrs: 100,
        },
    ];
    let head = vec![
        R2Function {
            name: "main".to_string(),
            addr: 0x1100,
            size: 220,
            ninstrs: 55,
        },
        R2Function {
            name: "handle_request".to_string(),
            addr: 0x2100,
            size: 380,
            ninstrs: 95,
        },
    ];

    let matches = binary_diff::match_functions(&base, &head);

    assert_eq!(matches.len(), 2);

    let main_match = matches.iter().find(|m| m.base_name == "main").unwrap();
    assert_eq!(main_match.head_name, "main");
    assert_eq!(main_match.match_method, "exact_name");

    let handler_match = matches
        .iter()
        .find(|m| m.base_name == "handle_request")
        .unwrap();
    assert_eq!(handler_match.head_name, "handle_request");
    assert_eq!(handler_match.match_method, "exact_name");
}

#[test]
fn function_matching_by_size_works_when_names_differ() {
    // Simulates stripped binaries where functions have synthetic names
    // but the same size and instruction count.
    let base = vec![R2Function {
        name: "fcn.00001000".to_string(),
        addr: 0x1000,
        size: 256,
        ninstrs: 64,
    }];
    let head = vec![R2Function {
        name: "fcn.00002000".to_string(),
        addr: 0x2000,
        size: 256,
        ninstrs: 64,
    }];

    let matches = binary_diff::match_functions(&base, &head);

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].base_name, "fcn.00001000");
    assert_eq!(matches[0].head_name, "fcn.00002000");
    assert_eq!(matches[0].match_method, "size_instrs");
}

#[test]
fn function_matching_fuzzy_size_within_20_percent() {
    // Functions with same (synthetic) name pattern but ~15% size difference.
    // No exact name match, no exact size match, but within 20% fuzzy range.
    let base = vec![R2Function {
        name: "fcn.0000a000".to_string(),
        addr: 0xa000,
        size: 100,
        ninstrs: 25,
    }];
    let head = vec![R2Function {
        name: "fcn.0000b000".to_string(),
        addr: 0xb000,
        size: 115, // 15% larger, within 20% threshold
        ninstrs: 29,
    }];

    let matches = binary_diff::match_functions(&base, &head);

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].match_method, "fuzzy_size");
    // Similarity should reflect the size difference
    assert!(matches[0].similarity < 1.0);
    assert!(matches[0].similarity > 0.5);
}

#[test]
fn function_matching_rejects_beyond_20_percent() {
    let base = vec![R2Function {
        name: "fcn.0000a000".to_string(),
        addr: 0xa000,
        size: 100,
        ninstrs: 25,
    }];
    let head = vec![R2Function {
        name: "fcn.0000b000".to_string(),
        addr: 0xb000,
        size: 200, // 100% larger, well beyond 20%
        ninstrs: 50,
    }];

    let matches = binary_diff::match_functions(&base, &head);

    assert!(matches.is_empty());
}

#[test]
fn function_matching_name_match_takes_precedence_over_size() {
    // Even if sizes differ, a name match should be preferred.
    let base = vec![R2Function {
        name: "validate_input".to_string(),
        addr: 0x1000,
        size: 100,
        ninstrs: 25,
    }];
    let head = vec![
        R2Function {
            name: "validate_input".to_string(),
            addr: 0x2000,
            size: 300, // very different size
            ninstrs: 75,
        },
        R2Function {
            name: "fcn.00003000".to_string(),
            addr: 0x3000,
            size: 100, // exact size match but different name
            ninstrs: 25,
        },
    ];

    let matches = binary_diff::match_functions(&base, &head);

    assert_eq!(matches.len(), 1);
    assert_eq!(matches[0].head_name, "validate_input");
    assert_eq!(matches[0].match_method, "exact_name");
}

#[test]
fn function_matching_no_double_matching() {
    // Once a head function is matched, it should not be matched again.
    let base = vec![
        R2Function {
            name: "fcn.00001000".to_string(),
            addr: 0x1000,
            size: 100,
            ninstrs: 25,
        },
        R2Function {
            name: "fcn.00002000".to_string(),
            addr: 0x2000,
            size: 100,
            ninstrs: 25,
        },
    ];
    let head = vec![R2Function {
        name: "fcn.00003000".to_string(),
        addr: 0x3000,
        size: 100,
        ninstrs: 25,
    }];

    let matches = binary_diff::match_functions(&base, &head);

    // Only one match possible since there's only one head function.
    assert_eq!(matches.len(), 1);
}

// ====================================================================
// R2 string diff tests
// ====================================================================

#[test]
fn diff_strings_detects_added_and_removed() {
    let base = vec![
        R2String {
            vaddr: 0x1000,
            string: "hello".to_string(),
            length: 5,
        },
        R2String {
            vaddr: 0x2000,
            string: "/cgi-bin/old".to_string(),
            length: 12,
        },
    ];
    let head = vec![
        R2String {
            vaddr: 0x1000,
            string: "hello".to_string(),
            length: 5,
        },
        R2String {
            vaddr: 0x3000,
            string: "system".to_string(),
            length: 6,
        },
    ];

    let diff = binary_diff::diff_strings(&base, &head);

    assert_eq!(diff.added.len(), 1);
    assert_eq!(diff.added[0].value, "system");
    assert_eq!(
        diff.added[0].security_tag,
        Some("DANGEROUS_CALL".to_string())
    );

    assert_eq!(diff.removed.len(), 1);
    assert_eq!(diff.removed[0].value, "/cgi-bin/old");
    assert_eq!(diff.removed[0].security_tag, Some("ENDPOINT".to_string()));
}

// ====================================================================
// Security change detection tests
// ====================================================================

#[test]
fn security_change_detection_flags_new_dangerous_call() {
    let matches = vec![];
    let string_diff = StringDiff {
        added: vec![StringEntry {
            value: "system".to_string(),
            address: "0x1000".to_string(),
            security_tag: Some("DANGEROUS_CALL".to_string()),
        }],
        removed: vec![],
    };

    let changes = binary_diff::detect_security_changes(&matches, &string_diff, &empty_ie_diff());

    assert!(!changes.is_empty());
    let change = changes
        .iter()
        .find(|c| c.change_type == "dangerous_call_added")
        .expect("should detect dangerous_call_added");
    assert_eq!(change.severity, "high");
    assert!(change.detail.contains("system"));
}

#[test]
fn security_change_detection_flags_removed_endpoint() {
    let matches = vec![];
    let string_diff = StringDiff {
        added: vec![],
        removed: vec![StringEntry {
            value: "/cgi-bin/admin".to_string(),
            address: "0x2000".to_string(),
            security_tag: Some("ENDPOINT".to_string()),
        }],
    };

    let changes = binary_diff::detect_security_changes(&matches, &string_diff, &empty_ie_diff());

    assert!(!changes.is_empty());
    let change = changes
        .iter()
        .find(|c| c.change_type == "endpoint_removed")
        .expect("should detect endpoint_removed");
    assert_eq!(change.severity, "info");
}

#[test]
fn security_change_detection_flags_new_endpoint() {
    let matches = vec![];
    let string_diff = StringDiff {
        added: vec![StringEntry {
            value: "/cgi-bin/upload".to_string(),
            address: "0x3000".to_string(),
            security_tag: Some("ENDPOINT".to_string()),
        }],
        removed: vec![],
    };

    let changes = binary_diff::detect_security_changes(&matches, &string_diff, &empty_ie_diff());

    let change = changes
        .iter()
        .find(|c| c.change_type == "endpoint_added")
        .expect("should detect endpoint_added");
    assert_eq!(change.severity, "medium");
}

#[test]
fn security_change_detection_flags_credential_changes() {
    let matches = vec![];
    let string_diff = StringDiff {
        added: vec![StringEntry {
            value: "admin_password".to_string(),
            address: "0x4000".to_string(),
            security_tag: Some("CREDENTIAL".to_string()),
        }],
        removed: vec![],
    };

    let changes = binary_diff::detect_security_changes(&matches, &string_diff, &empty_ie_diff());

    let change = changes
        .iter()
        .find(|c| c.change_type == "credential_added")
        .expect("should detect credential_added");
    assert_eq!(change.severity, "high");
}

#[test]
fn security_change_detection_flags_size_change_in_matched_function() {
    let matches = vec![FunctionMatch {
        base_name: "check_auth".to_string(),
        head_name: "check_auth".to_string(),
        base_offset: 0x1000,
        head_offset: 0x2000,
        base_size: 500,
        head_size: 100, // Significant shrinkage, possible validation removal
        base_ninstrs: 125,
        head_ninstrs: 25,
        similarity: 0.2,
        match_method: "exact_name".to_string(),
    }];
    let string_diff = StringDiff {
        added: vec![],
        removed: vec![],
    };

    let changes = binary_diff::detect_security_changes(&matches, &string_diff, &empty_ie_diff());

    let change = changes
        .iter()
        .find(|c| c.change_type == "validation_possibly_removed")
        .expect("should detect validation_possibly_removed for significantly shrunk auth/check function");
    assert_eq!(change.severity, "high");
    assert!(change.function_name.contains("check_auth"));
}

// ====================================================================
// R2 invocation error handling tests
// ====================================================================

#[test]
fn r2_function_list_returns_error_when_r2_missing() {
    // Use a non-existent path to ensure r2 cannot succeed
    let result = binary_diff::r2_function_list(std::path::Path::new("/nonexistent/binary"));

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    // Should mention r2 or radare2 in the error
    assert!(
        err_msg.contains("r2") || err_msg.contains("radare2"),
        "Error should mention r2/radare2, got: {err_msg}"
    );
}

#[test]
fn r2_strings_returns_error_when_r2_missing() {
    let result = binary_diff::r2_strings(std::path::Path::new("/nonexistent/binary"));

    assert!(result.is_err());
    let err_msg = result.unwrap_err().to_string();
    assert!(
        err_msg.contains("r2") || err_msg.contains("radare2"),
        "Error should mention r2/radare2, got: {err_msg}"
    );
}

// ====================================================================
// R2 JSON parsing tests (mock data, no r2 required)
// ====================================================================

#[test]
fn r2_function_json_parses_correctly() {
    let json = r#"[
        {"name": "main", "addr": 4096, "size": 200, "ninstrs": 50},
        {"name": "sym.handle_request", "addr": 8192, "size": 400, "ninstrs": 100}
    ]"#;

    let functions: Vec<R2Function> =
        serde_json::from_str(json).expect("should parse r2 aflj output");

    assert_eq!(functions.len(), 2);
    assert_eq!(functions[0].name, "main");
    assert_eq!(functions[0].addr, 4096);
    assert_eq!(functions[0].size, 200);
    assert_eq!(functions[0].ninstrs, 50);
    assert_eq!(functions[1].name, "sym.handle_request");
}

#[test]
fn r2_string_json_parses_correctly() {
    let json = r#"[
        {"vaddr": 4096, "string": "hello world", "length": 11},
        {"vaddr": 8192, "string": "/cgi-bin/admin", "length": 14}
    ]"#;

    let strings: Vec<R2String> = serde_json::from_str(json).expect("should parse r2 izj output");

    assert_eq!(strings.len(), 2);
    assert_eq!(strings[0].string, "hello world");
    assert_eq!(strings[0].vaddr, 4096);
    assert_eq!(strings[1].string, "/cgi-bin/admin");
}

#[test]
fn r2_function_json_handles_missing_ninstrs() {
    // r2 sometimes omits ninstrs for some entries
    let json = r#"[{"name": "entry0", "addr": 4096, "size": 16}]"#;

    let functions: Vec<R2Function> =
        serde_json::from_str(json).expect("should parse with default ninstrs");

    assert_eq!(functions.len(), 1);
    assert_eq!(functions[0].ninstrs, 0); // default
}

// ====================================================================
// Similarity computation tests
// ====================================================================

#[test]
fn function_match_similarity_is_1_when_sizes_equal() {
    let base = vec![R2Function {
        name: "main".to_string(),
        addr: 0x1000,
        size: 200,
        ninstrs: 50,
    }];
    let head = vec![R2Function {
        name: "main".to_string(),
        addr: 0x2000,
        size: 200,
        ninstrs: 50,
    }];

    let matches = binary_diff::match_functions(&base, &head);

    assert_eq!(matches.len(), 1);
    assert!((matches[0].similarity - 1.0).abs() < f64::EPSILON);
}

#[test]
fn function_match_similarity_decreases_with_size_difference() {
    let base = vec![R2Function {
        name: "process".to_string(),
        addr: 0x1000,
        size: 200,
        ninstrs: 50,
    }];
    let head = vec![R2Function {
        name: "process".to_string(),
        addr: 0x2000,
        size: 300,
        ninstrs: 75,
    }];

    let matches = binary_diff::match_functions(&base, &head);

    assert_eq!(matches.len(), 1);
    assert!(matches[0].similarity < 1.0);
    assert!(matches[0].similarity > 0.0);
}
