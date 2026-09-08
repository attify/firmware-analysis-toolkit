//! Parser and decryptor for Unitree UTPK (`.upk`) packages.
//!
//! The 16-byte TEA key is generated at runtime from the least-significant byte
//! of the header seed using the observed Unitree `GenerateCodeKey` recurrence.
//! No per-package keys, per-seed keys, or derived-key catalog are embedded.
//! UTPK does not expose a key-schedule version, so compatibility with a future
//! schedule must be established by validating the decrypted payload rather than
//! by adding target-specific keys.
//!
//! A UTPK container is a fixed `0x70`-byte header followed by a four-byte
//! `TEA\0` marker and a TEA-encrypted payload. For payload type `0x03` the
//! decrypted payload is an ordinary `tar` archive.
//!
//! Header layout (all integers little-endian):
//!
//! | Offset | Size | Field                                         |
//! |--------|------|-----------------------------------------------|
//! | 0x00   | 4    | magic `"UTPK"`                                |
//! | 0x08   | 8    | Unix timestamp                                |
//! | 0x10   | 8    | declared payload size (includes `TEA\0`)      |
//! | 0x18   | 1    | payload type (`0x03` = tar)                   |
//! | 0x1c   | 4    | seed (only the least-significant byte is used)|
//! | 0x20   | 16   | MD5 of bytes `[0x70..EOF]` (includes `TEA\0`) |
//! | 0x30   | 64   | NUL-terminated package name                   |
//! | 0x70   | 4    | `"TEA\0"` marker                              |
//! | 0x74   | ..   | TEA-encrypted payload                         |
//!
//! This module owns container parsing, validation, key derivation and TEA
//! decoding. Unpacking the decrypted tar into a filesystem is deliberately left
//! to the caller so that path-safety policy lives next to the extraction code.

use std::error::Error;
use std::fmt;

use md5::{Digest, Md5};

/// Container magic at offset `0x00`.
pub const UTPK_MAGIC: [u8; 4] = *b"UTPK";
/// Fixed header length; the encrypted region begins here.
pub const HEADER_LEN: usize = 0x70;
/// Marker at offset `0x70`, immediately before the ciphertext.
pub const TEA_MARKER: [u8; 4] = *b"TEA\0";
/// Payload type indicating the decrypted bytes are a `tar` archive.
pub const PAYLOAD_TYPE_TAR: u8 = 0x03;

const TEA_DELTA: u32 = 0x9e37_79b9;
const TEA_ROUNDS: u32 = 16;

/// Parsed UTPK header fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UtpkHeader {
    pub timestamp: u64,
    /// Declared size of the payload region, counting the four `TEA\0` bytes.
    pub declared_payload_size: u64,
    pub payload_type: u8,
    pub seed: u32,
    /// MD5 over `[0x70..EOF]`, as stored at offset `0x20`.
    pub payload_md5: [u8; 16],
    pub name: String,
}

impl UtpkHeader {
    /// The least-significant seed byte — the only part that affects the key.
    pub fn seed_byte(&self) -> u8 {
        (self.seed & 0xff) as u8
    }
}

/// A validated, decrypted UTPK payload.
#[derive(Debug, Clone)]
pub struct DecodedUpk {
    pub header: UtpkHeader,
    /// Decrypted payload bytes (a `tar` archive when `payload_type == 0x03`).
    pub payload: Vec<u8>,
}

/// Errors produced while recognising, validating or decoding a UTPK container.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UtpkError {
    /// Fewer bytes than a header + marker — not a UTPK we can act on.
    TooSmall { len: usize },
    /// Missing the `"UTPK"` magic; the input is simply not a UTPK container.
    NotUtpk,
    /// Recognised container, but the payload type is not one we can unpack.
    UnsupportedPayloadType(u8),
    /// Declared payload size disagrees with the actual file length.
    DeclaredSizeMismatch { declared: u64, actual: u64 },
    /// The `TEA\0` marker is absent at offset `0x70`.
    MissingTeaMarker,
    /// Ciphertext length is zero.
    EmptyCiphertext,
    /// Ciphertext length is not a multiple of the 8-byte TEA block.
    CiphertextNotBlockAligned { len: usize },
    /// Stored MD5 does not match the payload region — corrupt or truncated.
    Md5Mismatch {
        expected: [u8; 16],
        actual: [u8; 16],
    },
}

impl fmt::Display for UtpkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            UtpkError::TooSmall { len } => {
                write!(f, "input is too small for a UTPK container ({len} bytes)")
            }
            UtpkError::NotUtpk => write!(f, "input is not a UTPK container (missing UTPK magic)"),
            UtpkError::UnsupportedPayloadType(t) => {
                write!(
                    f,
                    "unsupported UTPK payload type {t:#04x} (only tar/0x03 is supported)"
                )
            }
            UtpkError::DeclaredSizeMismatch { declared, actual } => write!(
                f,
                "UTPK declared payload size {declared} does not match actual {actual}"
            ),
            UtpkError::MissingTeaMarker => {
                write!(
                    f,
                    "UTPK payload is missing the TEA\\0 marker at offset 0x70"
                )
            }
            UtpkError::EmptyCiphertext => write!(f, "UTPK ciphertext is empty"),
            UtpkError::CiphertextNotBlockAligned { len } => write!(
                f,
                "UTPK ciphertext length {len} is not a multiple of the 8-byte TEA block"
            ),
            UtpkError::Md5Mismatch { expected, actual } => write!(
                f,
                "UTPK payload MD5 mismatch: expected {}, computed {}",
                hex16(expected),
                hex16(actual)
            ),
        }
    }
}

impl Error for UtpkError {}

fn hex16(bytes: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for b in bytes {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Return `true` if `bytes` begins with the UTPK magic. Cheap sniff used by the
/// CLI to decide whether to take the UTPK decode path before extraction.
pub fn is_utpk(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[..4] == UTPK_MAGIC
}

/// Parse and validate the fixed header, without touching the payload.
pub fn parse_header(bytes: &[u8]) -> Result<UtpkHeader, UtpkError> {
    if bytes.len() < HEADER_LEN + TEA_MARKER.len() {
        return Err(UtpkError::TooSmall { len: bytes.len() });
    }
    if bytes[..4] != UTPK_MAGIC {
        return Err(UtpkError::NotUtpk);
    }

    let timestamp = u64::from_le_bytes(bytes[0x08..0x10].try_into().unwrap());
    let declared_payload_size = u64::from_le_bytes(bytes[0x10..0x18].try_into().unwrap());
    let payload_type = bytes[0x18];
    let seed = u32::from_le_bytes(bytes[0x1c..0x20].try_into().unwrap());
    let mut payload_md5 = [0u8; 16];
    payload_md5.copy_from_slice(&bytes[0x20..0x30]);
    let name = parse_c_string(&bytes[0x30..0x70]);

    Ok(UtpkHeader {
        timestamp,
        declared_payload_size,
        payload_type,
        seed,
        payload_md5,
        name,
    })
}

fn parse_c_string(field: &[u8]) -> String {
    let end = field.iter().position(|&b| b == 0).unwrap_or(field.len());
    String::from_utf8_lossy(&field[..end]).into_owned()
}

/// Fully validate and decrypt a UTPK container into its decoded payload.
///
/// Validation order surfaces the most actionable error first: structural
/// (magic, size, marker, alignment) before cryptographic (MD5, key). A
/// recognised-but-corrupt container yields a specific [`UtpkError`] rather than
/// silently producing empty output.
pub fn decode(bytes: &[u8]) -> Result<DecodedUpk, UtpkError> {
    let header = parse_header(bytes)?;

    if header.payload_type != PAYLOAD_TYPE_TAR {
        return Err(UtpkError::UnsupportedPayloadType(header.payload_type));
    }

    let payload_region = &bytes[HEADER_LEN..];
    let actual_payload_size = payload_region.len() as u64;
    if header.declared_payload_size != actual_payload_size {
        return Err(UtpkError::DeclaredSizeMismatch {
            declared: header.declared_payload_size,
            actual: actual_payload_size,
        });
    }

    if payload_region.len() < TEA_MARKER.len() || payload_region[..4] != TEA_MARKER {
        return Err(UtpkError::MissingTeaMarker);
    }

    let ciphertext = &payload_region[TEA_MARKER.len()..];
    if ciphertext.is_empty() {
        return Err(UtpkError::EmptyCiphertext);
    }
    if !ciphertext.len().is_multiple_of(8) {
        return Err(UtpkError::CiphertextNotBlockAligned {
            len: ciphertext.len(),
        });
    }

    // MD5 covers the whole payload region, marker included.
    let actual_md5 = md5_digest(payload_region);
    if actual_md5 != header.payload_md5 {
        return Err(UtpkError::Md5Mismatch {
            expected: header.payload_md5,
            actual: actual_md5,
        });
    }

    let key = derive_key(header.seed_byte());
    let payload = tea_decrypt(ciphertext, &key);

    Ok(DecodedUpk { header, payload })
}

/// Build a valid UTPK container around `plaintext` — the inverse of [`decode`].
///
/// `plaintext.len()` must be a multiple of eight. Encrypts with the generated
/// key for `seed_byte` and fills in a correct declared size and payload MD5.
/// Primarily for tests and round-tripping.
pub fn encode(
    seed_byte: u8,
    payload_type: u8,
    name: &str,
    plaintext: &[u8],
) -> Result<Vec<u8>, UtpkError> {
    let key = derive_key(seed_byte);
    let ciphertext = tea_encrypt(plaintext, &key);

    let mut payload = Vec::with_capacity(TEA_MARKER.len() + ciphertext.len());
    payload.extend_from_slice(&TEA_MARKER);
    payload.extend_from_slice(&ciphertext);

    let mut bytes = vec![0u8; HEADER_LEN];
    bytes[..4].copy_from_slice(&UTPK_MAGIC);
    bytes[0x10..0x18].copy_from_slice(&(payload.len() as u64).to_le_bytes());
    bytes[0x18] = payload_type;
    bytes[0x1c..0x20].copy_from_slice(&(seed_byte as u32).to_le_bytes());
    bytes[0x20..0x30].copy_from_slice(&md5_digest(&payload));
    let name_bytes = name.as_bytes();
    let n = name_bytes.len().min(63);
    bytes[0x30..0x30 + n].copy_from_slice(&name_bytes[..n]);

    bytes.extend_from_slice(&payload);
    Ok(bytes)
}

fn md5_digest(bytes: &[u8]) -> [u8; 16] {
    let mut hasher = Md5::new();
    hasher.update(bytes);
    hasher.finalize().into()
}

/// Decrypt a TEA ciphertext whose length is a multiple of eight bytes.
///
/// Data and key words are little-endian `u32`. Standard TEA with delta
/// `0x9e3779b9` and sixteen rounds; the decrypt sum starts at `delta * 16`.
pub fn tea_decrypt(ciphertext: &[u8], key: &[u8; 16]) -> Vec<u8> {
    let k = key_words(key);
    let mut out = Vec::with_capacity(ciphertext.len());
    for block in ciphertext.chunks_exact(8) {
        let mut v0 = u32::from_le_bytes(block[0..4].try_into().unwrap());
        let mut v1 = u32::from_le_bytes(block[4..8].try_into().unwrap());
        let mut sum = TEA_DELTA.wrapping_mul(TEA_ROUNDS);
        for _ in 0..TEA_ROUNDS {
            v1 = v1.wrapping_sub(
                (v0 << 4).wrapping_add(k[2]) ^ v0.wrapping_add(sum) ^ (v0 >> 5).wrapping_add(k[3]),
            );
            v0 = v0.wrapping_sub(
                (v1 << 4).wrapping_add(k[0]) ^ v1.wrapping_add(sum) ^ (v1 >> 5).wrapping_add(k[1]),
            );
            sum = sum.wrapping_sub(TEA_DELTA);
        }
        out.extend_from_slice(&v0.to_le_bytes());
        out.extend_from_slice(&v1.to_le_bytes());
    }
    out
}

/// TEA encryption — the inverse of [`tea_decrypt`]. Present so tests can build
/// synthetic UTPK containers without shipping vendor firmware.
pub fn tea_encrypt(plaintext: &[u8], key: &[u8; 16]) -> Vec<u8> {
    assert!(
        plaintext.len().is_multiple_of(8),
        "TEA plaintext must be a multiple of 8 bytes"
    );
    let k = key_words(key);
    let mut out = Vec::with_capacity(plaintext.len());
    for block in plaintext.chunks_exact(8) {
        let mut v0 = u32::from_le_bytes(block[0..4].try_into().unwrap());
        let mut v1 = u32::from_le_bytes(block[4..8].try_into().unwrap());
        let mut sum = 0u32;
        for _ in 0..TEA_ROUNDS {
            sum = sum.wrapping_add(TEA_DELTA);
            v0 = v0.wrapping_add(
                (v1 << 4).wrapping_add(k[0]) ^ v1.wrapping_add(sum) ^ (v1 >> 5).wrapping_add(k[1]),
            );
            v1 = v1.wrapping_add(
                (v0 << 4).wrapping_add(k[2]) ^ v0.wrapping_add(sum) ^ (v0 >> 5).wrapping_add(k[3]),
            );
        }
        out.extend_from_slice(&v0.to_le_bytes());
        out.extend_from_slice(&v1.to_le_bytes());
    }
    out
}

fn key_words(key: &[u8; 16]) -> [u32; 4] {
    [
        u32::from_le_bytes(key[0..4].try_into().unwrap()),
        u32::from_le_bytes(key[4..8].try_into().unwrap()),
        u32::from_le_bytes(key[8..12].try_into().unwrap()),
        u32::from_le_bytes(key[12..16].try_into().unwrap()),
    ]
}

/// Derive the 16-byte TEA key for a given seed byte.
///
/// Unitree stores a 32-bit little-endian seed in the UTPK header but its
/// generator consumes only the least-significant byte. Each subsequent key
/// byte applies the same byte permutation to the previous state and adds its
/// zero-based position, with all arithmetic wrapping modulo 256.
///
/// This implements the currently observed `GenerateCodeKey` schedule. Exact
/// compatibility is tested against externally supplied UPK/tar pairs so the
/// crate does not need to ship vendor-derived key material or firmware.
pub fn derive_key(seed_byte: u8) -> [u8; 16] {
    let mut key = [0u8; 16];
    let mut state = code_key_permute(seed_byte);
    key[0] = state;

    for (index, byte) in key.iter_mut().enumerate().skip(1) {
        state = code_key_permute(state).wrapping_add(index as u8);
        *byte = state;
    }

    key
}

/// The byte transformation used by Unitree's `CodeKey::HByte` routine.
fn code_key_permute(value: u8) -> u8 {
    0x7a_u8
        .wrapping_add(value & 0x11)
        .wrapping_sub(value & 0xee)
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEED: u8 = 0x2a;

    /// Build a valid synthetic UTPK around an arbitrary (already 8-aligned)
    /// plaintext, encrypting with the key for `seed_byte`.
    fn build_upk(seed_byte: u8, payload_type: u8, plaintext: &[u8]) -> Vec<u8> {
        encode(seed_byte, payload_type, "demo", plaintext).expect("valid synthetic package")
    }

    #[test]
    fn tea_round_trips() {
        let key = std::array::from_fn(|index| (index as u8).wrapping_mul(17));
        let plaintext: Vec<u8> = (0u8..=255).cycle().take(256).collect();
        let cipher = tea_encrypt(&plaintext, &key);
        assert_ne!(cipher, plaintext);
        assert_eq!(tea_decrypt(&cipher, &key), plaintext);
    }

    #[test]
    fn header_exposes_only_the_effective_seed_byte() {
        let mut upk = build_upk(TEST_SEED, PAYLOAD_TYPE_TAR, b"12345678");
        upk[0x1c..0x20].copy_from_slice(&0x4433_222au32.to_le_bytes());
        let header = parse_header(&upk).unwrap();
        assert_eq!(header.seed, 0x4433_222a);
        assert_eq!(header.seed_byte(), TEST_SEED);
    }

    #[test]
    fn decode_round_trips_synthetic_container() {
        let plaintext = b"hello, unitree UTPK payload!!!!!"; // 32 bytes, 8-aligned
        let upk = build_upk(TEST_SEED, PAYLOAD_TYPE_TAR, plaintext);
        let decoded = decode(&upk).expect("decode succeeds");
        assert_eq!(decoded.header.seed_byte(), TEST_SEED);
        assert_eq!(decoded.header.name, "demo");
        assert_eq!(decoded.payload, plaintext);
    }

    #[test]
    fn rejects_input_too_small() {
        assert_eq!(decode(b"UTPK").unwrap_err(), UtpkError::TooSmall { len: 4 });
    }

    #[test]
    fn rejects_non_utpk() {
        let mut buf = vec![0u8; HEADER_LEN + 8];
        buf[..4].copy_from_slice(b"ZZZZ");
        assert_eq!(parse_header(&buf).unwrap_err(), UtpkError::NotUtpk);
    }

    #[test]
    fn rejects_unsupported_payload_type() {
        let upk = build_upk(TEST_SEED, 0x07, b"12345678");
        assert_eq!(
            decode(&upk).unwrap_err(),
            UtpkError::UnsupportedPayloadType(0x07)
        );
    }

    #[test]
    fn rejects_declared_size_mismatch() {
        let mut upk = build_upk(TEST_SEED, PAYLOAD_TYPE_TAR, b"12345678");
        // Corrupt the declared size field.
        upk[0x10..0x18].copy_from_slice(&9999u64.to_le_bytes());
        assert!(matches!(
            decode(&upk).unwrap_err(),
            UtpkError::DeclaredSizeMismatch { .. }
        ));
    }

    #[test]
    fn rejects_missing_tea_marker() {
        let mut upk = build_upk(TEST_SEED, PAYLOAD_TYPE_TAR, b"12345678");
        upk[HEADER_LEN..HEADER_LEN + 4].copy_from_slice(b"XXXX");
        // MD5 now covers the tampered marker, so recompute it to isolate the
        // marker check from the MD5 check.
        let md5 = md5_digest(&upk[HEADER_LEN..]);
        upk[0x20..0x30].copy_from_slice(&md5);
        assert_eq!(decode(&upk).unwrap_err(), UtpkError::MissingTeaMarker);
    }

    #[test]
    fn rejects_md5_mismatch() {
        let mut upk = build_upk(TEST_SEED, PAYLOAD_TYPE_TAR, b"12345678");
        // Flip a ciphertext byte; MD5 over the payload region no longer matches.
        let last = upk.len() - 1;
        upk[last] ^= 0xff;
        assert!(matches!(
            decode(&upk).unwrap_err(),
            UtpkError::Md5Mismatch { .. }
        ));
    }

    #[test]
    fn rejects_unaligned_ciphertext() {
        // 8-byte plaintext → 8-byte ciphertext; append one stray byte and fix
        // declared size + MD5 so alignment is the only remaining fault.
        let mut upk = build_upk(TEST_SEED, PAYLOAD_TYPE_TAR, b"12345678");
        upk.push(0x00);
        let payload_len = upk.len() - HEADER_LEN;
        upk[0x10..0x18].copy_from_slice(&(payload_len as u64).to_le_bytes());
        let md5 = md5_digest(&upk[HEADER_LEN..]);
        upk[0x20..0x30].copy_from_slice(&md5);
        assert_eq!(
            decode(&upk).unwrap_err(),
            UtpkError::CiphertextNotBlockAligned { len: 9 }
        );
    }
}
