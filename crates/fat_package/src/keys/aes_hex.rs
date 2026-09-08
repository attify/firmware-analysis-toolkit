#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AsciiHexAesKey {
    pub offset: usize,
    pub bit_length: u32,
    pub decoded: Vec<u8>,
    pub confidence: String,
    pub validated: bool,
}

pub fn find_ascii_hex_aes_keys(data: &[u8], has_symmetric_crypto: bool) -> Vec<AsciiHexAesKey> {
    let mut keys = Vec::new();
    let mut start = None;

    for (index, byte) in data.iter().copied().enumerate() {
        if byte.is_ascii_hexdigit() {
            start.get_or_insert(index);
            continue;
        }

        if let Some(run_start) = start.take() {
            collect_ascii_hex_aes_key(data, run_start, index, has_symmetric_crypto, &mut keys);
        }
    }

    if let Some(run_start) = start {
        collect_ascii_hex_aes_key(data, run_start, data.len(), has_symmetric_crypto, &mut keys);
    }

    keys
}

fn collect_ascii_hex_aes_key(
    data: &[u8],
    start: usize,
    end: usize,
    has_symmetric_crypto: bool,
    keys: &mut Vec<AsciiHexAesKey>,
) {
    let bit_length = match end - start {
        32 => 128,
        48 => 192,
        64 => 256,
        _ => return,
    };
    let Some(decoded) = decode_hex_ascii(&data[start..end]) else {
        return;
    };
    let expected_key_bytes = (bit_length / 8) as usize;
    if decoded.len() != expected_key_bytes {
        return;
    }

    keys.push(AsciiHexAesKey {
        offset: start,
        bit_length,
        decoded,
        confidence: if has_symmetric_crypto {
            "probable".into()
        } else {
            "possible".into()
        },
        validated: true,
    });
}

fn decode_hex_ascii(hex: &[u8]) -> Option<Vec<u8>> {
    if !hex.len().is_multiple_of(2) {
        return None;
    }

    let mut decoded = Vec::with_capacity(hex.len() / 2);
    for pair in hex.chunks_exact(2) {
        let high = hex_nibble(pair[0])?;
        let low = hex_nibble(pair[1])?;
        decoded.push((high << 4) | low);
    }
    Some(decoded)
}

fn hex_nibble(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}
