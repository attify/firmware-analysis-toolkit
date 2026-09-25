use fat_core::mcu_inspection::{
    ArtifactIdentity, ByteMeasurements, ImageMeasurements, RepetitionMeasurements, UniformRegion,
};
use sha2::{Digest, Sha256};
use std::collections::HashSet;

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
            repetition: measure_repetition(bytes),
        },
    }
}

/// Neutral measurements over the original bytes. Exact whole-image periods are
/// bounded to aligned units; we do not infer why copies exist or modify input.
pub fn measure_repetition(bytes: &[u8]) -> RepetitionMeasurements {
    const BLOCK: usize = 16;
    let mut result = RepetitionMeasurements {
        block_size: BLOCK,
        copies: 1,
        ..Default::default()
    };
    result.total_block_count = bytes.len() / BLOCK;
    let mut seen = HashSet::new();
    for block in bytes.chunks_exact(BLOCK) {
        if !seen.insert(block) {
            result.duplicate_block_count += 1;
        }
    }
    // Prefix-function on complete 16-byte blocks: linear comparisons even
    // for an almost-uniform image with a different last byte. Uniform input
    // remains fill rather than thousands of nominal image copies.
    if bytes.len() >= 2 * BLOCK
        && bytes.len().is_multiple_of(BLOCK)
        && bytes.iter().any(|b| *b != bytes[0])
    {
        let count = bytes.len() / BLOCK;
        let block = |i: usize| &bytes[i * BLOCK..(i + 1) * BLOCK];
        let mut prefix = vec![0usize; count];
        for i in 1..count {
            let mut matched = prefix[i - 1];
            while matched > 0 && block(i) != block(matched) {
                matched = prefix[matched - 1];
            }
            if block(i) == block(matched) {
                matched += 1;
            }
            prefix[i] = matched;
        }
        let period = count - prefix[count - 1];
        if period < count && count.is_multiple_of(period) {
            let unit = period * BLOCK;
            result.repeated_unit_bytes = Some(unit as u64);
            result.copies = count / period;
            result.duplicate_blocks_from_copies = count - period;
        }
    }
    let unit = result
        .repeated_unit_bytes
        .map(|n| n as usize)
        .unwrap_or(bytes.len());
    let mut uniform_seen = HashSet::new();
    for block in bytes[..unit].chunks_exact(BLOCK) {
        if block.iter().all(|b| *b == block[0]) && !uniform_seen.insert(block[0]) {
            result.duplicate_uniform_blocks += 1;
        }
    }
    result.unexplained_duplicate_blocks = result
        .duplicate_block_count
        .saturating_sub(result.duplicate_blocks_from_copies + result.duplicate_uniform_blocks);
    let mut offset = 0;
    while offset < bytes.len() {
        let start = offset;
        let byte = bytes[offset];
        while offset < bytes.len() && bytes[offset] == byte {
            offset += 1;
        }
        if offset - start >= 128 {
            if result.uniform_regions.len() < 64 {
                result.uniform_regions.push(UniformRegion {
                    offset: start as u64,
                    length: (offset - start) as u64,
                    byte,
                });
            } else {
                result.uniform_regions_truncated = true;
            }
        }
    }
    result
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

#[cfg(test)]
mod repetition_tests {
    use super::*;

    #[test]
    fn duplicate_halves_and_fill_explain_all_block_repetitions() {
        let mut bytes: Vec<u8> = (0u128..816).flat_map(u128::to_le_bytes).collect();
        bytes.resize(16384, 0);
        bytes.extend_from_within(..);
        let report = serde_json::to_value(measure_image("synthetic", &bytes)).unwrap();
        let repetition = &report["bytes"]["repetition"];
        assert_eq!(repetition["repeated_unit_bytes"], 16384);
        assert_eq!(repetition["copies"], 2);
        assert_eq!(repetition["duplicate_block_count"], 1232);
        assert_eq!(repetition["unexplained_duplicate_blocks"], 0);
        assert_eq!(report["identity"]["total_bytes"], 32768);
    }

    #[test]
    fn repeated_regions_require_exact_equality() {
        let mut bytes: Vec<u8> = (0u128..256).flat_map(u128::to_le_bytes).collect();
        bytes.extend_from_within(..);
        bytes[6000] ^= 1;
        let report = serde_json::to_value(measure_image("synthetic", &bytes)).unwrap();
        assert!(report["bytes"]["repetition"]["repeated_unit_bytes"].is_null());
        assert!(
            report["bytes"]["repetition"]["unexplained_duplicate_blocks"]
                .as_u64()
                .unwrap()
                > 0
        );
    }

    #[test]
    fn almost_uniform_image_with_many_divisors_has_no_exact_period() {
        let mut bytes = vec![0; 16 * 720_720];
        *bytes.last_mut().unwrap() = 1;
        let measured = measure_repetition(&bytes);
        assert_eq!(measured.repeated_unit_bytes, None);
        assert_eq!(measured.unexplained_duplicate_blocks, 0);
        assert_eq!(measured.duplicate_uniform_blocks, 720_718);
    }

    #[test]
    fn whole_image_period_detection_preserves_non_power_of_two_units() {
        let unit: Vec<u8> = (0u128..3).flat_map(u128::to_le_bytes).collect();
        let result = measure_repetition(&unit.repeat(3));
        assert_eq!(result.repeated_unit_bytes, Some(48));
        assert_eq!(result.copies, 3);
        assert_eq!(result.duplicate_blocks_from_copies, 6);
    }
}
