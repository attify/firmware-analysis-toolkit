use crate::report::Report;
use fat_analyze::{
    bmc::{inspect_bytes, BmcOptions},
    boot_env::EnvScanOptions,
};
use fat_core::bmc::BmcInspectionReport;
use serde_json::{json, Value};
use std::{collections::BTreeSet, error::Error, fs::File, io::Read, path::Path};

type DynResult<T> = Result<T, Box<dyn Error>>;
const MAX_INPUT_BYTES: u64 = 512 * 1024 * 1024;

pub fn run(
    file: &Path,
    json_output: bool,
    sarif: bool,
    details: bool,
    env_offset: Option<u64>,
    env_size: Option<u64>,
    fail_on_warning: bool,
) -> DynResult<()> {
    let input = File::open(file)?;
    if input.metadata()?.len() > MAX_INPUT_BYTES {
        return Err("BMC inspection accepts images up to 512 MiB".into());
    }
    let mut bytes = Vec::new();
    input.take(MAX_INPUT_BYTES + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > MAX_INPUT_BYTES {
        return Err("BMC inspection accepts images up to 512 MiB".into());
    }
    let region = match (env_offset, env_size) {
        (Some(offset), Some(size)) => Some((offset, size)),
        (None, None) => None,
        _ => return Err("--env-offset and --env-size must be supplied together".into()),
    };
    let options = BmcOptions {
        environment: EnvScanOptions {
            region,
            ..Default::default()
        },
    };
    let report = inspect_bytes(&bytes, &file.to_string_lossy(), &options)?;
    if sarif {
        println!(
            "{}",
            serde_json::to_string_pretty(&sarif_report(&report, file)?)?
        );
    } else if json_output {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("{}", render(&report, details));
    }
    if fail_on_warning
        && report
            .findings
            .iter()
            .any(|f| matches!(f.level.as_str(), "warning" | "error"))
    {
        return Err("BMC inspection reported warnings (--fail-on-warning)".into());
    }
    Ok(())
}

pub fn parse_number(value: &str) -> Result<u64, String> {
    match value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        Some(hex) => u64::from_str_radix(hex, 16),
        None => value.parse(),
    }
    .map_err(|_| "expected an unsigned decimal or hexadecimal number".into())
}

fn render(report: &BmcInspectionReport, details: bool) -> String {
    let name = Path::new(&report.artifact_path)
        .file_name()
        .unwrap_or_default()
        .to_string_lossy();
    let mut view = Report::new(&format!("BMC inspection · {name}"));
    if !report.identity.is_empty() {
        view.section("Platform evidence");
        for item in &report.identity {
            let label = match item.category.as_str() {
                "firmware-stack-marker" => "Firmware marker",
                "compatible-string" => "Compatible string",
                other => other,
            };
            view.kv(label, &item.value);
            if details {
                view.kv(
                    "Located at",
                    format!("0x{:08x}: {}", item.offset, item.evidence),
                );
            }
        }
    }
    view.section("Image");
    view.kv("Size", format!("{} bytes", report.image_size));
    view.kv("SHA256", &report.sha256);
    for version in &report.bootloader_versions {
        view.kv(
            "Bootloader string",
            format!("{} at 0x{:08x}", version.context, version.offset),
        );
    }
    if !report.layout.regions.is_empty() {
        view.section("Flash layout");
        let rows = report
            .layout
            .regions
            .iter()
            .filter(|r| details || r.depth == 0)
            .map(|r| {
                vec![
                    format!("0x{:08x}", r.offset),
                    r.format.clone(),
                    r.size
                        .map(|s| format!("{s} bytes"))
                        .unwrap_or_else(|| "unknown span".into()),
                ]
            })
            .collect::<Vec<_>>();
        view.table(&["Offset", "Format", "Size"], &rows);
    }
    if !report.fit.blobs.is_empty() {
        view.section("FIT authentication metadata");
        for blob in &report.fit.blobs {
            view.kv(
                "FIT",
                format!("0x{:08x} · {} bytes", blob.offset, blob.size),
            );
            if let Some(description) = &blob.description {
                view.kv("Description", description);
            }
            if let Some(config) = &blob.default_configuration {
                view.kv("Default configuration", config);
            }
            if !blob.complete {
                view.kv("Metadata", "Incomplete; see JSON diagnostics");
            }
            let rows = blob
                .images
                .iter()
                .map(|image| {
                    let algorithms = image
                        .hashes
                        .iter()
                        .filter_map(|h| h.algorithm.as_deref())
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect::<Vec<_>>()
                        .join(", ");
                    vec![
                        image.name.clone(),
                        algorithms,
                        image.signatures.len().to_string(),
                    ]
                })
                .collect::<Vec<_>>();
            if !rows.is_empty() {
                view.table(&["Image", "Hash algorithms", "Signature nodes"], &rows);
            }
            for config in &blob.configurations {
                if details || blob.default_configuration.as_deref() == Some(&config.name) {
                    let references = config
                        .references
                        .iter()
                        .map(|r| format!("{}={}", r.property, r.images.join(", ")))
                        .collect::<Vec<_>>()
                        .join("; ");
                    if !references.is_empty() {
                        view.kv(&config.name, references);
                    }
                    for sig in &config.signatures {
                        view.kv(
                            "Configuration signature",
                            format!(
                                "{}: {} ({} bytes)",
                                sig.node_path,
                                sig.algorithm.as_deref().unwrap_or("unspecified algorithm"),
                                sig.value_size
                            ),
                        );
                    }
                }
            }
            if details {
                for image in &blob.images {
                    for hash in &image.hashes {
                        if let Some(value) = &hash.value_hex {
                            view.kv(&hash.node_path, value);
                        }
                    }
                    for sig in &image.signatures {
                        view.kv(
                            &sig.node_path,
                            format!(
                                "{} · key {} · {} bytes",
                                sig.algorithm.as_deref().unwrap_or("unspecified algorithm"),
                                sig.key_name_hint.as_deref().unwrap_or("unspecified"),
                                sig.value_size
                            ),
                        );
                    }
                }
            }
        }
    }
    if !report.fit.control_keys.is_empty() {
        view.section("Device-tree key metadata");
        for key in &report.fit.control_keys {
            view.kv(
                &key.node_path,
                format!(
                    "{} at 0x{:08x}",
                    key.algorithm.as_deref().unwrap_or("unspecified algorithm"),
                    key.offset
                ),
            );
            if let Some(required) = &key.required {
                view.kv("Stored required policy", required);
            }
        }
    }
    if !report.environment_scan.environments.is_empty() {
        view.section("Stored U-Boot environments");
        for env in &report.environment_scan.environments {
            view.kv(
                "Region",
                format!(
                    "0x{:08x} · {} bytes · {} · CRC valid ({})",
                    env.offset, env.size, env.format, env.crc_endianness
                ),
            );
            if let Some(flag) = env.redundancy_flag {
                view.kv("Redundancy flag", format!("0x{flag:02x}"));
            }
            view.kv("Variables", env.variables.len().to_string());
            let rows = env
                .variables
                .iter()
                .filter(|v| {
                    details
                        || matches!(
                            v.key.as_str(),
                            "bootcmd" | "bootargs" | "verify" | "sig_check" | "bootdelay"
                        )
                })
                .map(|v| {
                    vec![
                        v.key.clone(),
                        v.value.clone(),
                        format!("0x{:08x}", v.offset),
                    ]
                })
                .collect::<Vec<_>>();
            if !rows.is_empty() {
                view.table(&["Variable", "Stored value", "Offset"], &rows);
            }
        }
    }
    if details && !report.trust_markers.is_empty() {
        view.section("Located trust markers");
        let rows = report
            .trust_markers
            .iter()
            .map(|m| {
                vec![
                    format!("0x{:08x}", m.offset),
                    m.kind.clone(),
                    m.context.clone(),
                ]
            })
            .collect::<Vec<_>>();
        view.table(&["Offset", "Kind", "Context"], &rows);
    }
    if !report.findings.is_empty() {
        view.section("Observations");
        for finding in &report.findings {
            let p = view.palette();
            let level = if finding.level == "warning" {
                p.warn("warning")
            } else {
                p.info(&finding.level)
            };
            view.text(format!(
                "{level} at 0x{:08x}: {}",
                finding.offset, finding.message
            ));
            if details {
                view.kv("Rule", &finding.rule_id);
            }
        }
    }
    view.finish()
}

fn sarif_report(report: &BmcInspectionReport, file: &Path) -> DynResult<Value> {
    let canonical = file.canonicalize()?;
    #[cfg(unix)]
    let path_bytes = {
        use std::os::unix::ffi::OsStrExt;
        canonical.as_os_str().as_bytes().to_vec()
    };
    #[cfg(not(unix))]
    let path_bytes = {
        let path = canonical
            .to_str()
            .ok_or("cannot encode this filename as a file URI")?
            .replace('\\', "/");
        let normalized = if let Some(unc) = path.strip_prefix("//?/UNC/") {
            format!("//{unc}")
        } else {
            path.strip_prefix("//?/").unwrap_or(&path).to_owned()
        };
        normalized.into_bytes()
    };
    let encoded = path_bytes
        .into_iter()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"/-._~:".contains(&b) {
                char::from(b).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect::<String>();
    let uri = if cfg!(windows) && encoded.starts_with("//") {
        format!("file:{encoded}")
    } else if encoded.starts_with('/') {
        format!("file://{encoded}")
    } else {
        format!("file:///{encoded}")
    };
    let rule_ids = report
        .findings
        .iter()
        .map(|f| f.rule_id.as_str())
        .collect::<BTreeSet<_>>();
    let rules = rule_ids
        .iter()
        .map(|id| json!({"id":id,"shortDescription":{"text":rule_description(id)}}))
        .collect::<Vec<_>>();
    let results = report.findings.iter().map(|f| json!({
        "ruleId": f.rule_id, "level": f.level, "message": {"text": f.message},
        "locations": [{"physicalLocation": {"artifactLocation": {"uri":uri,"index":0}, "region":{"byteOffset":f.offset,"byteLength":f.length}}}],
        "properties": {"nodePath":f.node_path,"evidenceKind":"static-firmware"}
    })).collect::<Vec<_>>();
    Ok(json!({
        "$schema":"https://json.schemastore.org/sarif-2.1.0.json", "version":"2.1.0",
        "runs":[{"tool":{"driver":{"name":"FAT","semanticVersion":env!("CARGO_PKG_VERSION"),"informationUri":"https://github.com/attify/firmware-analysis-toolkit","rules":rules}},
            "artifacts":[{"location":{"uri":uri},"length":report.image_size,"hashes":{"sha-256":report.sha256}}],
            "results":results,
            "properties":{"analysis":"bmc-inspection/v1","fitDiagnostics":report.fit.diagnostics,"environmentDiagnostics":report.environment_scan.diagnostics,"environmentSearchLimited":report.environment_scan.search_limited,"diagnostics":report.diagnostics}
        }]
    }))
}

fn rule_description(id: &str) -> &str {
    match id {
        "BOOT-FIT-HASH-ONLY" => {
            "FIT has image hashes without image or configuration signature nodes"
        }
        "BOOT-FIT-SIGNATURE-METADATA" => "FIT signature metadata located",
        "BOOT-ENV-CHECK-DISABLED" => "Stored environment contains a disabled verification variable",
        "BMC-PRIVATE-KEY-MARKER" => "Private-key PEM header located",
        "BMC-PUBLIC-KEY-MARKER" => "Public-key or certificate PEM header located",
        _ => "Trust-relevant firmware string located",
    }
}
