use fat_package::relations::signature_fit::{
    analyze_rsa_pss_sha256_fit, ByteRange, SignatureByteOrder, SignatureFitInput,
    SignatureFitPublicKey, SignatureFitVerdict,
};
use sha2::{Digest, Sha256};

#[test]
fn recognizes_rsa_pss_sha256_fit_after_public_operation() {
    let signature_offset = 4;
    let signature_len = 80;
    let mut firmware = vec![0x41; signature_offset + signature_len + 12];
    firmware[signature_offset..signature_offset + signature_len].fill(0);

    let message_hash = sha256_with_zeroed_ranges(
        &firmware,
        &[ByteRange {
            offset: signature_offset,
            length: signature_len,
        }],
    );
    let em = pss_sha256_em(&message_hash, signature_len, b"12345678");
    firmware[signature_offset..signature_offset + signature_len]
        .copy_from_slice(&em.iter().rev().copied().collect::<Vec<_>>());

    let report = analyze_rsa_pss_sha256_fit(SignatureFitInput {
        firmware: &firmware,
        signature: ByteRange {
            offset: signature_offset,
            length: signature_len,
        },
        zeroed_ranges: vec![ByteRange {
            offset: signature_offset,
            length: signature_len,
        }],
        public_key: SignatureFitPublicKey {
            bit_length: (signature_len * 8) as u32,
            public_exponent: 1,
            modulus_be: vec![0xff; signature_len],
        },
        signature_byte_order: SignatureByteOrder::LittleEndian,
    })
    .expect("signature fit analysis succeeds");

    assert_eq!(report.verdict, SignatureFitVerdict::Fit);
    assert!(report.trailer_ok);
    assert!(report.db_separator_ok);
    assert!(report.message_hash_ok);
    assert_eq!(report.salt_length, Some(8));
    assert_eq!(report.salt.as_deref(), Some(b"12345678".as_slice()));
    assert_eq!(report.encoded_message_tail_hex, "f657c4fac596d6bc");
}

#[test]
fn reports_no_fit_when_pss_hash_does_not_match_zeroed_firmware() {
    let signature_offset = 8;
    let signature_len = 80;
    let mut firmware = vec![0x55; signature_offset + signature_len + 12];
    firmware[signature_offset..signature_offset + signature_len].fill(0);

    let message_hash = sha256_with_zeroed_ranges(
        &firmware,
        &[ByteRange {
            offset: signature_offset,
            length: signature_len,
        }],
    );
    let em = pss_sha256_em(&message_hash, signature_len, b"ABCDEFGH");
    firmware[signature_offset..signature_offset + signature_len].copy_from_slice(&em);
    firmware[0] ^= 0xff;

    let report = analyze_rsa_pss_sha256_fit(SignatureFitInput {
        firmware: &firmware,
        signature: ByteRange {
            offset: signature_offset,
            length: signature_len,
        },
        zeroed_ranges: vec![ByteRange {
            offset: signature_offset,
            length: signature_len,
        }],
        public_key: SignatureFitPublicKey {
            bit_length: (signature_len * 8) as u32,
            public_exponent: 1,
            modulus_be: vec![0xff; signature_len],
        },
        signature_byte_order: SignatureByteOrder::BigEndian,
    })
    .expect("signature fit analysis succeeds");

    assert_eq!(report.verdict, SignatureFitVerdict::NoFit);
    assert!(report.trailer_ok);
    assert!(report.db_separator_ok);
    assert!(!report.message_hash_ok);
    assert_eq!(report.salt_length, Some(8));
    assert_eq!(report.salt.as_deref(), Some(b"ABCDEFGH".as_slice()));
}

#[test]
fn reports_no_fit_instead_of_error_when_signature_integer_is_out_of_range() {
    let firmware = vec![0xff; 80];

    let report = analyze_rsa_pss_sha256_fit(SignatureFitInput {
        firmware: &firmware,
        signature: ByteRange {
            offset: 0,
            length: 80,
        },
        zeroed_ranges: vec![ByteRange {
            offset: 0,
            length: 80,
        }],
        public_key: SignatureFitPublicKey {
            bit_length: 640,
            public_exponent: 65537,
            modulus_be: vec![0x80; 80],
        },
        signature_byte_order: SignatureByteOrder::BigEndian,
    })
    .expect("out-of-range signature is a no-fit result, not a fatal analysis error");

    assert_eq!(report.verdict, SignatureFitVerdict::NoFit);
    assert!(!report.rsa_public_operation_ok);
    assert!(!report.trailer_ok);
    assert!(!report.db_separator_ok);
    assert!(!report.message_hash_ok);
    assert_eq!(report.salt_length, None);
    assert_eq!(report.salt, None);
}

fn sha256_with_zeroed_ranges(firmware: &[u8], ranges: &[ByteRange]) -> [u8; 32] {
    let mut normalized = firmware.to_vec();
    for range in ranges {
        normalized[range.offset..range.offset + range.length].fill(0);
    }
    Sha256::digest(&normalized).into()
}

fn pss_sha256_em(message_hash: &[u8; 32], em_len: usize, salt: &[u8]) -> Vec<u8> {
    let hash_len = 32;
    let db_len = em_len - hash_len - 1;
    let ps_len = db_len - salt.len() - 1;

    let mut h_input = Vec::new();
    h_input.extend_from_slice(&[0u8; 8]);
    h_input.extend_from_slice(message_hash);
    h_input.extend_from_slice(salt);
    let h: [u8; 32] = Sha256::digest(&h_input).into();

    let mut db = vec![0u8; ps_len];
    db.push(0x01);
    db.extend_from_slice(salt);

    let mask = mgf1_sha256(&h, db_len);
    let masked_db = db
        .iter()
        .zip(mask)
        .map(|(left, right)| left ^ right)
        .collect::<Vec<_>>();

    let mut em = masked_db;
    em.extend_from_slice(&h);
    em.push(0xbc);
    em
}

fn mgf1_sha256(seed: &[u8], length: usize) -> Vec<u8> {
    let mut mask = Vec::with_capacity(length);
    let mut counter = 0u32;
    while mask.len() < length {
        let mut hasher = Sha256::new();
        hasher.update(seed);
        hasher.update(counter.to_be_bytes());
        mask.extend_from_slice(&hasher.finalize());
        counter += 1;
    }
    mask.truncate(length);
    mask
}
