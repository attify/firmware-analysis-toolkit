use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use std::error::Error;
use std::fmt;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ByteRange {
    pub offset: usize,
    pub length: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureByteOrder {
    BigEndian,
    LittleEndian,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureFitPublicKey {
    pub bit_length: u32,
    pub public_exponent: u32,
    pub modulus_be: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureFitInput<'a> {
    pub firmware: &'a [u8],
    pub signature: ByteRange,
    pub zeroed_ranges: Vec<ByteRange>,
    pub public_key: SignatureFitPublicKey,
    pub signature_byte_order: SignatureByteOrder,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SignatureFitVerdict {
    Fit,
    NoFit,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureFitReport {
    pub verdict: SignatureFitVerdict,
    pub key_bits: u32,
    pub public_exponent: u32,
    pub signature_offset: usize,
    pub signature_length: usize,
    pub signature_byte_order: SignatureByteOrder,
    pub rsa_public_operation_ok: bool,
    pub trailer_ok: bool,
    pub db_separator_ok: bool,
    pub message_hash_ok: bool,
    pub salt_length: Option<usize>,
    pub salt: Option<Vec<u8>>,
    pub zeroed_firmware_sha256_hex: Option<String>,
    pub encoded_message_tail_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SignatureFitError {
    InvalidKeyLength,
    InvalidPublicExponent,
    SignatureRangeOutOfBounds,
    ZeroedRangeOutOfBounds,
    SignatureLengthMismatch { expected: usize, actual: usize },
    SignatureRepresentativeTooLarge,
    EncodedMessageTooShort,
}

impl fmt::Display for SignatureFitError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidKeyLength => write!(f, "invalid RSA key length"),
            Self::InvalidPublicExponent => write!(f, "invalid RSA public exponent"),
            Self::SignatureRangeOutOfBounds => write!(f, "signature range is outside the firmware"),
            Self::ZeroedRangeOutOfBounds => write!(f, "zeroed range is outside the firmware"),
            Self::SignatureLengthMismatch { expected, actual } => write!(
                f,
                "signature length is {actual} bytes, expected {expected} bytes for the RSA key"
            ),
            Self::SignatureRepresentativeTooLarge => {
                write!(
                    f,
                    "signature integer is greater than or equal to the modulus"
                )
            }
            Self::EncodedMessageTooShort => {
                write!(f, "encoded message is too short for PSS/SHA-256")
            }
        }
    }
}

impl Error for SignatureFitError {}

pub fn analyze_rsa_pss_sha256_fit(
    input: SignatureFitInput<'_>,
) -> Result<SignatureFitReport, SignatureFitError> {
    let k = validate_public_key(&input.public_key)?;
    validate_range(input.firmware, input.signature)
        .ok_or(SignatureFitError::SignatureRangeOutOfBounds)?;
    for range in &input.zeroed_ranges {
        validate_range(input.firmware, *range).ok_or(SignatureFitError::ZeroedRangeOutOfBounds)?;
    }
    if input.signature.length != k {
        return Err(SignatureFitError::SignatureLengthMismatch {
            expected: k,
            actual: input.signature.length,
        });
    }

    let signature =
        &input.firmware[input.signature.offset..input.signature.offset + input.signature.length];
    let em = match rsa_public_operation(signature, &input.public_key, input.signature_byte_order) {
        Ok(em) => em,
        Err(SignatureFitError::SignatureRepresentativeTooLarge) => {
            return Ok(SignatureFitReport {
                verdict: SignatureFitVerdict::NoFit,
                key_bits: input.public_key.bit_length,
                public_exponent: input.public_key.public_exponent,
                signature_offset: input.signature.offset,
                signature_length: input.signature.length,
                signature_byte_order: input.signature_byte_order,
                rsa_public_operation_ok: false,
                trailer_ok: false,
                db_separator_ok: false,
                message_hash_ok: false,
                salt_length: None,
                salt: None,
                zeroed_firmware_sha256_hex: None,
                encoded_message_tail_hex: String::new(),
            });
        }
        Err(err) => return Err(err),
    };
    let pss = analyze_pss_sha256_encoded_message(
        &em,
        input.public_key.bit_length,
        input.firmware,
        &input.zeroed_ranges,
    )?;

    Ok(SignatureFitReport {
        verdict: if pss.trailer_ok && pss.db_separator_ok && pss.message_hash_ok {
            SignatureFitVerdict::Fit
        } else {
            SignatureFitVerdict::NoFit
        },
        key_bits: input.public_key.bit_length,
        public_exponent: input.public_key.public_exponent,
        signature_offset: input.signature.offset,
        signature_length: input.signature.length,
        signature_byte_order: input.signature_byte_order,
        rsa_public_operation_ok: true,
        trailer_ok: pss.trailer_ok,
        db_separator_ok: pss.db_separator_ok,
        message_hash_ok: pss.message_hash_ok,
        salt_length: pss.salt_length,
        salt: pss.salt,
        zeroed_firmware_sha256_hex: pss.zeroed_firmware_sha256_hex,
        encoded_message_tail_hex: tail_hex(&em),
    })
}

fn validate_public_key(key: &SignatureFitPublicKey) -> Result<usize, SignatureFitError> {
    if key.bit_length == 0 || !key.bit_length.is_multiple_of(8) || key.modulus_be.is_empty() {
        return Err(SignatureFitError::InvalidKeyLength);
    }
    let k = (key.bit_length / 8) as usize;
    if key.modulus_be.len() != k {
        return Err(SignatureFitError::InvalidKeyLength);
    }
    if key.public_exponent == 0 {
        return Err(SignatureFitError::InvalidPublicExponent);
    }
    Ok(k)
}

fn validate_range(data: &[u8], range: ByteRange) -> Option<()> {
    let end = range.offset.checked_add(range.length)?;
    (end <= data.len()).then_some(())
}

fn rsa_public_operation(
    signature: &[u8],
    key: &SignatureFitPublicKey,
    byte_order: SignatureByteOrder,
) -> Result<Vec<u8>, SignatureFitError> {
    let mut signature_integer_bytes = signature.to_vec();
    if byte_order == SignatureByteOrder::LittleEndian {
        signature_integer_bytes.reverse();
    }

    let s = BigUint::from_bytes_be(&signature_integer_bytes);
    let n = BigUint::from_bytes_be(&key.modulus_be);
    if s >= n {
        return Err(SignatureFitError::SignatureRepresentativeTooLarge);
    }

    let e = BigUint::from(key.public_exponent);
    let m = s.modpow(&e, &n);
    let mut em = m.to_bytes_be();
    let k = (key.bit_length / 8) as usize;
    if em.len() < k {
        let mut padded = vec![0u8; k - em.len()];
        padded.extend_from_slice(&em);
        em = padded;
    }
    Ok(em)
}

struct PssShape {
    trailer_ok: bool,
    db_separator_ok: bool,
    message_hash_ok: bool,
    salt_length: Option<usize>,
    salt: Option<Vec<u8>>,
    zeroed_firmware_sha256_hex: Option<String>,
}

fn analyze_pss_sha256_encoded_message(
    em: &[u8],
    key_bits: u32,
    firmware: &[u8],
    zeroed_ranges: &[ByteRange],
) -> Result<PssShape, SignatureFitError> {
    let hash_len = 32usize;
    if em.len() < hash_len + 2 {
        return Err(SignatureFitError::EncodedMessageTooShort);
    }

    let db_len = em.len() - hash_len - 1;
    let (masked_db, rest) = em.split_at(db_len);
    let (h, trailer) = rest.split_at(hash_len);
    let trailer_ok = trailer == [0xbc];

    let db_mask = mgf1_sha256(h, db_len);
    let mut db = masked_db
        .iter()
        .zip(db_mask.iter())
        .map(|(left, right)| left ^ right)
        .collect::<Vec<_>>();
    clear_unused_pss_bits(&mut db, key_bits);

    let separator_index = db.iter().position(|byte| *byte != 0);
    let db_separator_ok = separator_index.is_some_and(|index| db[index] == 0x01);
    let salt = separator_index
        .filter(|index| db[*index] == 0x01)
        .map(|index| &db[index + 1..]);
    let salt_length = salt.map(|value| value.len());

    let (message_hash_ok, zeroed_firmware_sha256_hex) = if let Some(salt) = salt {
        let message_hash = firmware_sha256_with_zeroed_ranges(firmware, zeroed_ranges);
        let mut hasher = Sha256::new();
        hasher.update([0u8; 8]);
        hasher.update(message_hash);
        hasher.update(salt);
        let recomputed_h: [u8; 32] = hasher.finalize().into();
        (
            recomputed_h.as_slice() == h,
            Some(bytes_to_hex(&message_hash)),
        )
    } else {
        (false, None)
    };

    Ok(PssShape {
        trailer_ok,
        db_separator_ok,
        message_hash_ok,
        salt_length,
        salt: salt.map(|value| value.to_vec()),
        zeroed_firmware_sha256_hex,
    })
}

fn firmware_sha256_with_zeroed_ranges(firmware: &[u8], zeroed_ranges: &[ByteRange]) -> [u8; 32] {
    let mut normalized = firmware.to_vec();
    for range in zeroed_ranges {
        normalized[range.offset..range.offset + range.length].fill(0);
    }
    Sha256::digest(&normalized).into()
}

fn clear_unused_pss_bits(db: &mut [u8], key_bits: u32) {
    if db.is_empty() || key_bits == 0 {
        return;
    }
    let em_bits = key_bits.saturating_sub(1);
    let unused_bits = (8 * db.len() + 8 + 32 * 8).saturating_sub(em_bits as usize);
    if unused_bits > 0 && unused_bits < 8 {
        db[0] &= 0xffu8 >> unused_bits;
    }
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

fn tail_hex(bytes: &[u8]) -> String {
    let start = bytes.len().saturating_sub(8);
    bytes_to_hex(&bytes[start..])
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}
