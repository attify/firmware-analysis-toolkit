use fat_package::keys::{
    find_ascii_hex_aes_keys, find_ms_publickeyblob_base64_blobs, parse_ms_public_key_blob,
};

#[test]
fn parses_microsoft_rsa_publickeyblob_fields_and_modulus_order() {
    let modulus_le = (0..128).map(|value| value as u8).collect::<Vec<_>>();
    let mut blob = ms_publickeyblob(1024, 65537, &modulus_le);

    let parsed = parse_ms_public_key_blob(&blob).expect("valid PUBLICKEYBLOB parses");

    assert_eq!(parsed.bit_length, 1024);
    assert_eq!(parsed.public_exponent, 65537);
    assert_eq!(parsed.modulus_bytes, 128);
    assert_eq!(parsed.raw, blob);
    assert_eq!(
        parsed.modulus_be,
        modulus_le.iter().rev().copied().collect::<Vec<_>>()
    );
    assert!(parsed.pem_data.starts_with("-----BEGIN PUBLIC KEY-----"));

    blob[8] = b'B';
    assert!(parse_ms_public_key_blob(&blob).is_none());
}

#[test]
fn finds_base64_wrapped_publickeyblobs_with_offsets() {
    let modulus_le = vec![0xA5; 256];
    let blob = ms_publickeyblob(2048, 65537, &modulus_le);
    let encoded = base64_for_test(&blob);
    let data = format!("prefix:{encoded}:suffix");

    let blobs = find_ms_publickeyblob_base64_blobs(data.as_bytes());

    assert_eq!(blobs.len(), 1);
    assert_eq!(blobs[0].offset, "prefix:".len());
    assert_eq!(blobs[0].parsed.bit_length, 2048);
    assert_eq!(blobs[0].parsed.modulus_bytes, 256);
}

#[test]
fn detects_exact_length_ascii_hex_aes_keys_without_swallowing_longer_runs() {
    let data = b"x=00112233445566778899aabbccddeeff y=00112233445566778899aabbccddeeff00";

    let keys = find_ascii_hex_aes_keys(data, true);

    assert_eq!(keys.len(), 1);
    assert_eq!(keys[0].offset, 2);
    assert_eq!(keys[0].bit_length, 128);
    assert_eq!(keys[0].decoded.len(), 16);
    assert_eq!(keys[0].confidence, "probable");
    assert!(keys[0].validated);
}

fn ms_publickeyblob(bit_length: u32, public_exponent: u32, modulus_le: &[u8]) -> Vec<u8> {
    let mut blob = Vec::new();
    blob.extend_from_slice(&[0x06, 0x02, 0x00, 0x00, 0x0c, 0x24, 0x00, 0x00]);
    blob.extend_from_slice(b"RSA1");
    blob.extend_from_slice(&bit_length.to_le_bytes());
    blob.extend_from_slice(&public_exponent.to_le_bytes());
    blob.extend_from_slice(modulus_le);
    blob
}

fn base64_for_test(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(TABLE[(b0 >> 2) as usize] as char);
        out.push(TABLE[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        out.push(if chunk.len() > 1 {
            TABLE[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char
        } else {
            '='
        });
        out.push(if chunk.len() > 2 {
            TABLE[(b2 & 0x3f) as usize] as char
        } else {
            '='
        });
    }
    out
}
