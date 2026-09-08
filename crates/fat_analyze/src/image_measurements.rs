use fat_core::mcu_inspection::{ArtifactIdentity, ByteMeasurements, ImageMeasurements};
use sha2::{Digest, Sha256};

pub fn measure_image(path: impl Into<String>, bytes: &[u8]) -> ImageMeasurements {
    let total_bytes = bytes.len() as u64;
    let (trailing_uniform_byte, trailing_uniform_offset, trailing_uniform_bytes) =
        uniform_suffix(bytes);
    let content_prefix_bytes = trailing_uniform_offset.unwrap_or(total_bytes);
    let content_prefix = &bytes[..content_prefix_bytes as usize];

    ImageMeasurements {
        identity: ArtifactIdentity {
            path: path.into(),
            sha256: format!("{:x}", Sha256::digest(bytes)),
            total_bytes,
        },
        bytes: ByteMeasurements {
            total_bytes,
            content_prefix_bytes,
            trailing_uniform_byte,
            trailing_uniform_offset,
            trailing_uniform_bytes,
            trailing_uniform_percent: if total_bytes == 0 {
                0.0
            } else {
                trailing_uniform_bytes as f64 * 100.0 / total_bytes as f64
            },
            whole_entropy_bits_per_byte: shannon_entropy(bytes),
            content_entropy_bits_per_byte: (!content_prefix.is_empty())
                .then(|| shannon_entropy(content_prefix)),
        },
    }
}

fn uniform_suffix(bytes: &[u8]) -> (Option<u8>, Option<u64>, u64) {
    let Some(&last_byte) = bytes.last() else {
        return (None, None, 0);
    };

    let offset = bytes
        .iter()
        .rposition(|byte| *byte != last_byte)
        .map(|index| index + 1)
        .unwrap_or(0);
    let length = bytes.len() - offset;

    (Some(last_byte), Some(offset as u64), length as u64)
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }

    let mut frequencies = [0usize; 256];
    for byte in bytes {
        frequencies[*byte as usize] += 1;
    }

    let length = bytes.len() as f64;
    frequencies
        .into_iter()
        .filter(|count| *count != 0)
        .map(|count| {
            let probability = count as f64 / length;
            -probability * probability.log2()
        })
        .sum()
}
