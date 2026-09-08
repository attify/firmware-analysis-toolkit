use fat_package::keys::parse_ms_public_key_blob;
use fat_package::relations::signature_fit::{
    analyze_rsa_pss_sha256_fit, ByteRange, SignatureByteOrder, SignatureFitInput,
    SignatureFitPublicKey, SignatureFitReport, SignatureFitVerdict,
};
use serde::Serialize;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

type DynResult<T> = Result<T, Box<dyn Error>>;

pub(crate) fn run(
    firmware_path: &Path,
    key_blob_path: &Path,
    signature_offset: &str,
    signature_size: &str,
    signature_byte_order: &str,
    zero_ranges: &[String],
    output_dir: Option<&Path>,
    json: bool,
) -> DynResult<()> {
    let firmware = fs::read(firmware_path)?;
    let key_blob = fs::read(key_blob_path)?;
    let public_blob = parse_ms_public_key_blob(&key_blob).ok_or_else(|| {
        format!(
            "{} is not a valid Microsoft PUBLICKEYBLOB",
            key_blob_path.display()
        )
    })?;

    let signature = ByteRange {
        offset: parse_number(signature_offset)?,
        length: parse_number(signature_size)?,
    };
    let zeroed_ranges = if zero_ranges.is_empty() {
        vec![signature]
    } else {
        zero_ranges
            .iter()
            .map(|raw| parse_range(raw))
            .collect::<Result<Vec<_>, _>>()?
    };
    let byte_order = parse_byte_order(signature_byte_order)?;

    let report = analyze_rsa_pss_sha256_fit(SignatureFitInput {
        firmware: &firmware,
        signature,
        zeroed_ranges,
        public_key: SignatureFitPublicKey {
            bit_length: public_blob.bit_length,
            public_exponent: public_blob.public_exponent,
            modulus_be: public_blob.modulus_be,
        },
        signature_byte_order: byte_order,
    })?;
    let exported = if let Some(output_dir) = output_dir {
        Some(export_signature_artifacts(output_dir, &report)?)
    } else {
        None
    };

    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&SerializableReport::new(&report, exported.as_ref()))?
        );
    } else {
        print_human_report(&report);
        if let Some(exported) = exported.as_ref() {
            print_exported_artifacts(exported);
        }
    }

    Ok(())
}

fn print_human_report(report: &SignatureFitReport) {
    println!("Signature fit");
    println!("  scheme: rsa-pss-sha256");
    println!(
        "  key: RSA-{} e={}",
        report.key_bits, report.public_exponent
    );
    println!(
        "  signature: 0x{:x}..0x{:x} ({} bytes, {})",
        report.signature_offset,
        report.signature_offset + report.signature_length,
        report.signature_length,
        byte_order_label(report.signature_byte_order)
    );
    println!(
        "  rsa_public_operation: {}",
        ok_label(report.rsa_public_operation_ok)
    );
    println!("  pss_trailer: {}", ok_label(report.trailer_ok));
    println!("  pss_db: {}", ok_label(report.db_separator_ok));
    println!("  pss_hash: {}", ok_label(report.message_hash_ok));
    if let Some(salt_length) = report.salt_length {
        println!("  salt_length: {salt_length}");
    }
    println!("  em_tail: {}", report.encoded_message_tail_hex);
    println!("  verdict: {}", verdict_label(report.verdict));
}

fn export_signature_artifacts(
    output_dir: &Path,
    report: &SignatureFitReport,
) -> DynResult<ExportedSignatureArtifacts> {
    if report.verdict != SignatureFitVerdict::Fit {
        return Err("signature fit did not produce a verified salt to export".into());
    }
    fs::create_dir_all(output_dir)?;
    let salt = report
        .salt
        .as_ref()
        .ok_or("signature fit did not recover a PSS salt to export")?;
    let salt_path = output_dir.join("pss_salt.bin");
    fs::write(&salt_path, salt)?;
    let zeroed_firmware_sha256_path =
        if let Some(zeroed_firmware_sha256_hex) = &report.zeroed_firmware_sha256_hex {
            let path = output_dir.join("zeroed_firmware_sha256.txt");
            fs::write(&path, zeroed_firmware_sha256_hex)?;
            Some(path)
        } else {
            None
        };

    let exported = ExportedSignatureArtifacts {
        salt_path,
        zeroed_firmware_sha256_path,
        manifest_path: output_dir.join("signature_fit_manifest.json"),
    };
    fs::write(
        &exported.manifest_path,
        serde_json::to_string_pretty(&ExportManifest::new(report, &exported))?,
    )?;
    Ok(exported)
}

fn print_exported_artifacts(exported: &ExportedSignatureArtifacts) {
    println!("  exported_salt: {}", exported.salt_path.display());
    if let Some(path) = exported.zeroed_firmware_sha256_path.as_ref() {
        println!("  exported_zeroed_firmware_sha256: {}", path.display());
    }
    println!("  exported_manifest: {}", exported.manifest_path.display());
}

fn parse_byte_order(raw: &str) -> DynResult<SignatureByteOrder> {
    match raw {
        "big" | "be" | "big-endian" => Ok(SignatureByteOrder::BigEndian),
        "little" | "le" | "little-endian" => Ok(SignatureByteOrder::LittleEndian),
        _ => Err(format!("invalid --signature-byte-order {raw:?}; use big or little").into()),
    }
}

fn parse_range(raw: &str) -> DynResult<ByteRange> {
    if let Some((offset, length)) = raw.split_once(':') {
        return Ok(ByteRange {
            offset: parse_number(offset)?,
            length: parse_number(length)?,
        });
    }
    if let Some((start, end)) = raw.split_once("..") {
        let start = parse_number(start)?;
        let end = parse_number(end)?;
        if end < start {
            return Err(format!("invalid range {raw:?}: end is before start").into());
        }
        return Ok(ByteRange {
            offset: start,
            length: end - start,
        });
    }
    Err(format!("invalid range {raw:?}; use offset:length or start..end").into())
}

fn parse_number(raw: &str) -> DynResult<usize> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err("empty numeric value".into());
    }
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return usize::from_str_radix(hex, 16)
            .map_err(|err| format!("invalid hex value {raw:?}: {err}").into());
    }
    trimmed
        .parse::<usize>()
        .map_err(|err| format!("invalid numeric value {raw:?}: {err}").into())
}

fn ok_label(ok: bool) -> &'static str {
    if ok {
        "ok"
    } else {
        "no"
    }
}

fn verdict_label(verdict: SignatureFitVerdict) -> &'static str {
    match verdict {
        SignatureFitVerdict::Fit => "fit",
        SignatureFitVerdict::NoFit => "no-fit",
    }
}

fn byte_order_label(byte_order: SignatureByteOrder) -> &'static str {
    match byte_order {
        SignatureByteOrder::BigEndian => "big-endian",
        SignatureByteOrder::LittleEndian => "little-endian",
    }
}

#[derive(Serialize)]
struct SerializableReport<'a> {
    schema_version: &'static str,
    scheme: &'static str,
    verdict: &'a str,
    key_bits: u32,
    public_exponent: u32,
    signature_offset: usize,
    signature_length: usize,
    signature_byte_order: &'a str,
    rsa_public_operation_ok: bool,
    trailer_ok: bool,
    db_separator_ok: bool,
    message_hash_ok: bool,
    salt_length: Option<usize>,
    salt_hex: Option<String>,
    zeroed_firmware_sha256_hex: Option<&'a str>,
    exported_artifacts: Option<SerializableExportedArtifacts>,
    encoded_message_tail_hex: &'a str,
}

impl<'a> From<&'a SignatureFitReport> for SerializableReport<'a> {
    fn from(report: &'a SignatureFitReport) -> Self {
        Self::new(report, None)
    }
}

impl<'a> SerializableReport<'a> {
    fn new(report: &'a SignatureFitReport, exported: Option<&ExportedSignatureArtifacts>) -> Self {
        Self {
            schema_version: "signature-fit/v2",
            scheme: "rsa-pss-sha256",
            verdict: verdict_label(report.verdict),
            key_bits: report.key_bits,
            public_exponent: report.public_exponent,
            signature_offset: report.signature_offset,
            signature_length: report.signature_length,
            signature_byte_order: byte_order_label(report.signature_byte_order),
            rsa_public_operation_ok: report.rsa_public_operation_ok,
            trailer_ok: report.trailer_ok,
            db_separator_ok: report.db_separator_ok,
            message_hash_ok: report.message_hash_ok,
            salt_length: report.salt_length,
            salt_hex: report.salt.as_ref().map(|salt| bytes_to_hex(salt)),
            zeroed_firmware_sha256_hex: report.zeroed_firmware_sha256_hex.as_deref(),
            exported_artifacts: exported.map(SerializableExportedArtifacts::from),
            encoded_message_tail_hex: &report.encoded_message_tail_hex,
        }
    }
}

#[derive(Debug, Clone)]
struct ExportedSignatureArtifacts {
    salt_path: PathBuf,
    zeroed_firmware_sha256_path: Option<PathBuf>,
    manifest_path: PathBuf,
}

#[derive(Serialize)]
struct SerializableExportedArtifacts {
    salt_path: String,
    zeroed_firmware_sha256_path: Option<String>,
    manifest_path: String,
}

impl From<&ExportedSignatureArtifacts> for SerializableExportedArtifacts {
    fn from(exported: &ExportedSignatureArtifacts) -> Self {
        Self {
            salt_path: exported.salt_path.display().to_string(),
            zeroed_firmware_sha256_path: exported
                .zeroed_firmware_sha256_path
                .as_ref()
                .map(|path| path.display().to_string()),
            manifest_path: exported.manifest_path.display().to_string(),
        }
    }
}

#[derive(Serialize)]
struct ExportManifest<'a> {
    schema_version: &'static str,
    report: SerializableReport<'a>,
}

impl<'a> ExportManifest<'a> {
    fn new(report: &'a SignatureFitReport, exported: &ExportedSignatureArtifacts) -> Self {
        Self {
            schema_version: "signature-fit-artifacts/v2",
            report: SerializableReport::new(report, Some(exported)),
        }
    }
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>()
}
