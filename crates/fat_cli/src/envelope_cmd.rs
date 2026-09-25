use crate::schema_versions;
use fat_analyze::image_measurements::measure_repetition;
use fat_core::mcu_inspection::RepetitionMeasurements;
use serde::Serialize;
use std::path::Path;

type DynResult<T> = Result<T, Box<dyn std::error::Error>>;

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct EnvelopeReport {
    pub schema_version: &'static str,
    pub entropy: f64,
    pub confidence: f64,
    pub unique_byte_count: usize,
    pub duplicate_block_count: usize,
    pub total_block_count: usize,
    pub classification: String,
    pub ecb_assessment: String,
    pub reason: String,
    pub evidence: Vec<String>,
    pub likely_plaintext_header_len: Option<usize>,
    pub reference_prefix_len: Option<usize>,
    pub repetition: RepetitionMeasurements,
}

impl EnvelopeReport {
    pub fn is_encrypted_like(&self) -> bool {
        self.classification == "opaque-wrapper-likely"
    }
}

pub fn analyze_envelope(bytes: &[u8], reference: Option<&[u8]>) -> EnvelopeReport {
    let entropy = shannon_entropy(bytes);
    let unique_byte_count = count_unique_bytes(bytes);
    let repetition = measure_repetition(bytes);
    let duplicate_block_count = repetition.duplicate_block_count;
    let total_block_count = repetition.total_block_count;
    let reference_prefix_len = reference.map(|other| common_prefix_len(bytes, other));
    let likely_plaintext_header_len =
        reference_prefix_len.or_else(|| detect_plaintext_header_len(bytes, entropy));

    let mut evidence = vec![
        format!("Entropy: {:.2}/8.0", entropy),
        format!("Unique bytes: {unique_byte_count}/256"),
        format!("Duplicate 16-byte blocks: {duplicate_block_count} of {total_block_count}"),
    ];
    if let Some(unit) = repetition.repeated_unit_bytes {
        evidence.push(format!(
            "Exact repeated region: [0, 0x{unit:X}) repeats {} times across the file",
            repetition.copies
        ));
    }
    if duplicate_block_count > 0 {
        evidence.push(format!("Duplicate-block accounting: {} from exact copies, {} from uniform blocks, {} unexplained",
            repetition.duplicate_blocks_from_copies, repetition.duplicate_uniform_blocks, repetition.unexplained_duplicate_blocks));
    }
    for region in repetition.uniform_regions.iter().take(4) {
        evidence.push(format!(
            "Uniform 0x{:02X} region: [0x{:X}, 0x{:X})",
            region.byte,
            region.offset,
            region.offset + region.length
        ));
    }

    if let Some(prefix_len) = reference_prefix_len {
        evidence.push(format!("Shared prefix with reference: {prefix_len} bytes"));
    }

    if let Some(header_len) = likely_plaintext_header_len {
        evidence.push(format!("Likely plaintext header span: 0x{header_len:X}"));
    }

    let (classification, ecb_assessment, confidence, reason) =
        if total_block_count >= 16 && duplicate_block_count > total_block_count / 4 {
            (
                "repetitive-payload".to_string(),
                "not-indicated".to_string(),
                0.72,
                if repetition.unexplained_duplicate_blocks == 0 {
                    "repeated blocks are fully accounted for by exact copies and uniform fill"
                        .to_string()
                } else {
                    "repeated blocks observed; repetition alone does not establish encryption"
                        .to_string()
                },
            )
        } else if entropy >= 7.5 && unique_byte_count >= 200 && duplicate_block_count <= 1 {
            (
                "opaque-wrapper-likely".to_string(),
                if total_block_count >= 16 {
                    "ecb-unlikely".to_string()
                } else {
                    "insufficient-block-evidence".to_string()
                },
                0.93,
                "high entropy with minimal repeated AES-sized blocks suggests an opaque wrapper"
                    .to_string(),
            )
        } else {
            (
                "structured-or-plaintext-like".to_string(),
                "not-indicated".to_string(),
                0.61,
                "the byte distribution looks more structured than encrypted".to_string(),
            )
        };

    EnvelopeReport {
        schema_version: schema_versions::ENVELOPE_ANALYSIS_V1,
        entropy,
        confidence,
        unique_byte_count,
        duplicate_block_count,
        total_block_count,
        classification,
        ecb_assessment,
        reason,
        evidence,
        likely_plaintext_header_len,
        reference_prefix_len,
        repetition,
    }
}

pub fn run(file: &Path, reference: Option<&Path>, json_output: bool) -> DynResult<()> {
    if !file.is_file() {
        return Err(format!("file not found: {}", file.display()).into());
    }
    let bytes = std::fs::read(file)?;
    let reference_bytes = match reference {
        Some(path) => Some(std::fs::read(path)?),
        None => None,
    };
    let report = analyze_envelope(&bytes, reference_bytes.as_deref());
    if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        render_report(file, &report, reference.is_some());
    }
    Ok(())
}

pub fn render_report(file: &Path, report: &EnvelopeReport, has_reference: bool) {
    let palette = crate::style::Palette::stdout();
    if !palette.enabled() {
        println!("Envelope analysis: {}\n", file.display());
        println!(
            "Classification: {}",
            render_classification(&report.classification)
        );
        for line in &report.evidence {
            println!("- {line}");
        }
        return;
    }

    let (dot, classification) = match report.classification.as_str() {
        "opaque-wrapper-likely" => (
            palette.dot_warn(),
            palette.warn(render_classification(&report.classification)),
        ),
        _ => (
            palette.dot_muted(),
            palette.info(render_classification(&report.classification)),
        ),
    };

    let mut lines = vec![format!(
        "{dot} {classification} · confidence {}",
        palette.bar(report.confidence as f32, 12)
    )];
    lines.push(format!("· {}", palette.muted(&report.reason)));
    lines.push(format!(
        "{} · {}",
        palette.kv("entropy", format!("{:.2}/8.0", report.entropy)),
        palette.bar((report.entropy / 8.0) as f32, 12)
    ));

    lines.push(String::new());
    lines.push(palette.heading("Structure"));
    for line in report.evidence.iter().skip(1) {
        lines.push(format!("· {}", palette.muted(line)));
    }

    println!("{}", palette.panel("Envelope analysis", &lines));
    if !has_reference {
        println!(
            "{}",
            palette.next_hint(&format!("fat identify --file {}", file.display()))
        );
    }
}

pub fn render_classification(classification: &str) -> &str {
    match classification {
        "opaque-wrapper-likely" => "Opaque wrapper likely",
        "repetitive-payload" => "Repetitive payload",
        _ => "Structured or plaintext-like",
    }
}

fn count_unique_bytes(bytes: &[u8]) -> usize {
    let mut seen = [false; 256];
    for &byte in bytes {
        seen[byte as usize] = true;
    }
    seen.iter().filter(|flag| **flag).count()
}

fn shannon_entropy(bytes: &[u8]) -> f64 {
    if bytes.is_empty() {
        return 0.0;
    }
    let mut counts = [0usize; 256];
    for byte in bytes {
        counts[*byte as usize] += 1;
    }
    let len = bytes.len() as f64;
    counts
        .iter()
        .filter(|count| **count > 0)
        .map(|count| {
            let p = *count as f64 / len;
            -p * p.log2()
        })
        .sum()
}

fn common_prefix_len(left: &[u8], right: &[u8]) -> usize {
    left.iter()
        .zip(right.iter())
        .take_while(|(a, b)| a == b)
        .count()
}

fn detect_plaintext_header_len(bytes: &[u8], total_entropy: f64) -> Option<usize> {
    if bytes.len() < 96 {
        return None;
    }
    let header = &bytes[..32];
    let body = &bytes[32..usize::min(bytes.len(), 32 + 1024)];
    let header_entropy = shannon_entropy(header);
    let body_entropy = shannon_entropy(body);
    if header_entropy + 1.0 < body_entropy && total_entropy >= 6.5 {
        Some(32)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::analyze_envelope;

    fn pseudo_random_bytes(len: usize) -> Vec<u8> {
        let mut state: u32 = 0x1234_5678;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            state ^= state << 13;
            state ^= state >> 17;
            state ^= state << 5;
            out.push((state & 0xff) as u8);
        }
        out
    }

    #[test]
    fn high_entropy_blob_is_classified_as_opaque_wrapper_likely() {
        let report = analyze_envelope(&pseudo_random_bytes(8192), None);
        assert_eq!(report.classification, "opaque-wrapper-likely");
        assert!(
            report.entropy > 7.5,
            "expected high entropy, got {}",
            report.entropy
        );
    }

    #[test]
    fn evidence_contains_measurements_not_classification_prose() {
        let opaque = analyze_envelope(&pseudo_random_bytes(8192), None);
        let repetitive = analyze_envelope(&[b'A'; 4096], None);
        let structured = analyze_envelope(b"short structured input", None);

        for report in [&opaque, &repetitive, &structured] {
            assert!(
                report
                    .evidence
                    .iter()
                    .any(|line| line.starts_with("Entropy:")),
                "missing entropy measurement: {:?}",
                report.evidence
            );
            assert!(
                report
                    .evidence
                    .iter()
                    .any(|line| line.starts_with("Unique bytes:")),
                "missing unique-byte measurement: {:?}",
                report.evidence
            );
            assert!(
                report
                    .evidence
                    .iter()
                    .any(|line| line.starts_with("Duplicate 16-byte blocks:")),
                "missing duplicate-block measurement: {:?}",
                report.evidence
            );
            for interpretive_prefix in [
                "Opaque wrapper likely:",
                "ECB plausible:",
                "ECB unlikely:",
                "Plaintext or structured container",
            ] {
                assert!(
                    report
                        .evidence
                        .iter()
                        .all(|line| !line.starts_with(interpretive_prefix)),
                    "interpretive prose leaked into evidence: {:?}",
                    report.evidence
                );
            }
        }
    }

    #[test]
    fn repeated_16_byte_blocks_are_not_encryption_evidence() {
        let mut blob = Vec::new();
        for _ in 0..256 {
            blob.extend_from_slice(b"0123456789ABCDEF");
        }
        let report = analyze_envelope(&blob, None);
        assert_eq!(report.ecb_assessment, "not-indicated");
        assert!(report.duplicate_block_count > 0);
    }

    #[test]
    fn alternating_repeated_blocks_are_counted_exactly() {
        let repeated = [0x11u8; 16];
        let mut blob = Vec::with_capacity(65_536 * 16);
        for i in 0..65_536 {
            if i % 2 == 0 {
                blob.extend_from_slice(&(i as u128).to_le_bytes());
            } else {
                blob.extend_from_slice(&repeated);
            }
        }
        let report = analyze_envelope(&blob, None);
        assert_eq!(report.duplicate_block_count, 32_767);
        assert_eq!(report.total_block_count, 65_536);
        assert_eq!(report.ecb_assessment, "not-indicated");
    }

    #[test]
    fn reference_comparison_reports_longest_common_prefix() {
        let mut left = vec![0x55, 0xAA, 0x01, 0x02];
        left.extend_from_slice(&pseudo_random_bytes(512));
        let mut right = vec![0x55, 0xAA, 0x01, 0x02];
        right.extend_from_slice(&[0x99; 512]);

        let report = analyze_envelope(&left, Some(&right));
        assert_eq!(report.reference_prefix_len, Some(4));
    }

    #[test]
    fn low_entropy_blob_is_not_marked_as_opaque_wrapper() {
        let blob = vec![b'A'; 4096];
        let report = analyze_envelope(&blob, None);
        assert_ne!(report.classification, "opaque-wrapper-likely");
    }

    #[test]
    fn encrypted_like_gate_uses_typed_envelope_classifications() {
        let opaque = analyze_envelope(&pseudo_random_bytes(8192), None);
        let repetitive = analyze_envelope(&[b'A'; 4096], None);
        let structured = analyze_envelope(b"short structured input", None);

        assert!(opaque.is_encrypted_like());
        assert!(!repetitive.is_encrypted_like());
        assert!(!structured.is_encrypted_like());
    }
}
