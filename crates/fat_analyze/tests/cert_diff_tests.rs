use fat_analyze::cert_diff::{diff_certificates, diff_certificates_from_info, parse_x509_output};
use std::path::Path;

#[test]
fn cert_diff_detects_key_size_change() {
    let base_output = r#"subject=CN = My Device CA, O = TestCorp, C = US
notBefore=Jan  1 00:00:00 2024 GMT
notAfter=Dec 31 23:59:59 2034 GMT
Modulus=ABC123DEF456
            Public-Key: (1024 bit)
        Signature Algorithm: sha256WithRSAEncryption
"#;
    let head_output = r#"subject=CN = My Device CA, O = TestCorp, C = US
notBefore=Jan  1 00:00:00 2024 GMT
notAfter=Dec 31 23:59:59 2034 GMT
Modulus=ABC123DEF456
            Public-Key: (2048 bit)
        Signature Algorithm: sha256WithRSAEncryption
"#;

    let base_info = parse_x509_output(base_output).unwrap();
    let head_info = parse_x509_output(head_output).unwrap();

    assert_eq!(base_info.key_bits, 1024);
    assert_eq!(head_info.key_bits, 2048);

    let diff = diff_certificates_from_info("certs/device.pem", &base_info, &head_info);
    assert_eq!(diff.base_key_bits, Some(1024));
    assert_eq!(diff.head_key_bits, Some(2048));
    // Same modulus => no key rotation
    assert!(!diff.key_rotated);
}

#[test]
fn cert_diff_detects_key_rotation() {
    let base_output = r#"subject=CN = Device Root CA, O = VendorCo
notBefore=Jan  1 00:00:00 2020 GMT
notAfter=Dec 31 23:59:59 2030 GMT
Modulus=A1B2C3D4E5F6001122334455
            Public-Key: (2048 bit)
        Signature Algorithm: sha256WithRSAEncryption
"#;
    let head_output = r#"subject=CN = Device Root CA v2, O = VendorCo
notBefore=Jun  1 00:00:00 2025 GMT
notAfter=Jun  1 00:00:00 2035 GMT
Modulus=DEADBEEF99887766554433221100
            Public-Key: (2048 bit)
        Signature Algorithm: sha512WithRSAEncryption
"#;

    let base_info = parse_x509_output(base_output).unwrap();
    let head_info = parse_x509_output(head_output).unwrap();

    let diff = diff_certificates_from_info("certs/root.pem", &base_info, &head_info);

    // Different modulus => key rotation
    assert!(
        diff.key_rotated,
        "different modulus hashes should indicate key rotation"
    );
    assert_ne!(diff.base_modulus_hash, diff.head_modulus_hash);

    // Subject changed
    assert_eq!(
        diff.base_subject.as_deref(),
        Some("CN = Device Root CA, O = VendorCo")
    );
    assert_eq!(
        diff.head_subject.as_deref(),
        Some("CN = Device Root CA v2, O = VendorCo")
    );

    // Signature algorithm changed
    assert_eq!(
        diff.base_signature_algorithm.as_deref(),
        Some("sha256WithRSAEncryption")
    );
    assert_eq!(
        diff.head_signature_algorithm.as_deref(),
        Some("sha512WithRSAEncryption")
    );

    // Expiry changed
    assert_eq!(
        diff.base_not_after.as_deref(),
        Some("Dec 31 23:59:59 2030 GMT")
    );
    assert_eq!(
        diff.head_not_after.as_deref(),
        Some("Jun  1 00:00:00 2035 GMT")
    );
}

#[test]
fn cert_diff_handles_missing_openssl_gracefully() {
    // When openssl is not found or the cert file does not exist,
    // diff_certificates should return an error, not panic.
    let nonexistent_base = Path::new("/nonexistent/base.pem");
    let nonexistent_head = Path::new("/nonexistent/head.pem");

    let result = diff_certificates(nonexistent_base, nonexistent_head);
    assert!(
        result.is_err(),
        "should return error for nonexistent cert files"
    );

    let err = result.unwrap_err();
    // The error kind should indicate the problem clearly
    let err_msg = err.to_string();
    assert!(
        err_msg.contains("openssl") || err_msg.contains("failed"),
        "error message should mention openssl or failure: got: {err_msg}"
    );
}
