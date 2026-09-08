#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MsPublicKeyBlob {
    pub raw: Vec<u8>,
    pub bit_length: u32,
    pub public_exponent: u32,
    pub modulus_bytes: usize,
    pub modulus_be: Vec<u8>,
    pub pem_data: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocatedMsPublicKeyBlob {
    pub offset: usize,
    pub encoded: Vec<u8>,
    pub parsed: MsPublicKeyBlob,
}

pub fn parse_ms_public_key_blob(decoded: &[u8]) -> Option<MsPublicKeyBlob> {
    if decoded.len() < 20 {
        return None;
    }
    if decoded[0] != 0x06 || decoded[1] != 0x02 || decoded.get(8..12)? != b"RSA1" {
        return None;
    }

    let bit_length = u32::from_le_bytes(decoded.get(12..16)?.try_into().ok()?);
    if bit_length == 0 || bit_length % 8 != 0 {
        return None;
    }

    let modulus_bytes = (bit_length / 8) as usize;
    let expected_len = 20usize.checked_add(modulus_bytes)?;
    if decoded.len() < expected_len {
        return None;
    }

    let public_exponent = u32::from_le_bytes(decoded.get(16..20)?.try_into().ok()?);
    let mut modulus_be = decoded.get(20..expected_len)?.to_vec();
    modulus_be.reverse();
    let spki = rsa_public_key_spki_der(&modulus_be, public_exponent);
    let pem_data = format_pem("PUBLIC KEY", &base64_encode(&spki));

    Some(MsPublicKeyBlob {
        raw: decoded[..expected_len].to_vec(),
        bit_length,
        public_exponent,
        modulus_bytes,
        modulus_be,
        pem_data,
    })
}

pub fn find_ms_publickeyblob_base64_blobs(data: &[u8]) -> Vec<LocatedMsPublicKeyBlob> {
    let mut blobs = Vec::new();
    let mut start = None;

    for (index, byte) in data.iter().copied().enumerate() {
        if is_base64_byte(byte) {
            start.get_or_insert(index);
            continue;
        }

        if let Some(run_start) = start.take() {
            collect_ms_publickeyblob_candidate(data, run_start, index, &mut blobs);
        }
    }

    if let Some(run_start) = start {
        collect_ms_publickeyblob_candidate(data, run_start, data.len(), &mut blobs);
    }

    blobs
}

fn collect_ms_publickeyblob_candidate(
    data: &[u8],
    start: usize,
    end: usize,
    blobs: &mut Vec<LocatedMsPublicKeyBlob>,
) {
    let encoded = &data[start..end];
    if encoded.len() < 180 || encoded.len() > 400 || !encoded.starts_with(b"BgIAAA") {
        return;
    }
    let Some(decoded) = decode_base64_ascii(encoded) else {
        return;
    };
    let Some(parsed) = parse_ms_public_key_blob(&decoded) else {
        return;
    };
    blobs.push(LocatedMsPublicKeyBlob {
        offset: start,
        encoded: encoded.to_vec(),
        parsed,
    });
}

fn is_base64_byte(byte: u8) -> bool {
    matches!(byte, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'+' | b'/' | b'=')
}

fn decode_base64_ascii(input: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(input.len() * 3 / 4);
    let mut quartet = [0u8; 4];
    let mut qlen = 0usize;

    for &byte in input {
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            b'=' => 64,
            _ => return None,
        };
        quartet[qlen] = value;
        qlen += 1;
        if qlen == 4 {
            if quartet[0] == 64 || quartet[1] == 64 {
                return None;
            }
            out.push((quartet[0] << 2) | (quartet[1] >> 4));
            if quartet[2] != 64 {
                out.push((quartet[1] << 4) | (quartet[2] >> 2));
            }
            if quartet[3] != 64 {
                out.push((quartet[2] << 6) | quartet[3]);
            }
            qlen = 0;
        }
    }

    if qlen != 0 {
        return None;
    }
    Some(out)
}

fn format_pem(label: &str, base64_str: &str) -> String {
    let wrapped = base64_str
        .chars()
        .collect::<Vec<_>>()
        .chunks(64)
        .map(|chunk| chunk.iter().collect::<String>())
        .collect::<Vec<_>>()
        .join("\n");
    format!("-----BEGIN {label}-----\n{wrapped}\n-----END {label}-----")
}

fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(input.len().div_ceil(3) * 4);
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

fn rsa_public_key_spki_der(modulus_be: &[u8], exponent: u32) -> Vec<u8> {
    let mut rsa_public_key = Vec::new();
    rsa_public_key.extend(der_integer(modulus_be));
    rsa_public_key.extend(der_integer(&minimal_be_u32(exponent)));
    let rsa_public_key = der_sequence(&rsa_public_key);

    let algorithm = der_sequence(
        &[
            &[
                0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
            ][..],
            &[0x05, 0x00][..],
        ]
        .concat(),
    );

    let mut bit_string_payload = Vec::with_capacity(rsa_public_key.len() + 1);
    bit_string_payload.push(0);
    bit_string_payload.extend(rsa_public_key);

    let mut spki_payload = Vec::new();
    spki_payload.extend(algorithm);
    spki_payload.extend(der_tagged(0x03, &bit_string_payload));
    der_sequence(&spki_payload)
}

fn der_sequence(payload: &[u8]) -> Vec<u8> {
    der_tagged(0x30, payload)
}

fn der_integer(bytes: &[u8]) -> Vec<u8> {
    let mut value = bytes
        .iter()
        .skip_while(|byte| **byte == 0)
        .copied()
        .collect::<Vec<_>>();
    if value.is_empty() {
        value.push(0);
    }
    if value[0] & 0x80 != 0 {
        value.insert(0, 0);
    }
    der_tagged(0x02, &value)
}

fn der_tagged(tag: u8, payload: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    out.extend(der_len(payload.len()));
    out.extend(payload);
    out
}

fn der_len(len: usize) -> Vec<u8> {
    if len < 0x80 {
        return vec![len as u8];
    }
    let mut bytes = Vec::new();
    let mut value = len;
    while value > 0 {
        bytes.push((value & 0xff) as u8);
        value >>= 8;
    }
    bytes.reverse();
    let mut out = vec![0x80 | bytes.len() as u8];
    out.extend(bytes);
    out
}

fn minimal_be_u32(value: u32) -> Vec<u8> {
    value
        .to_be_bytes()
        .iter()
        .skip_while(|byte| **byte == 0)
        .copied()
        .collect()
}
