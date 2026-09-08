use crate::DynResult;
use clap::{Args, Subcommand};
use fat_analyze::edge_ai::{scan_edge_ai_root, EdgeAiFormat};
use fat_core::finding::FindingSubject;
use std::io;
use std::path::PathBuf;

const EDGE_AI_SCAN_LONG_ABOUT: &str = "Scan any extracted rootfs or model corpus directory using the canonical Rust scanner.\n\n\
The scan reports normal FAT findings plus structured metadata when visible:\n  \
- MAGIK/JZDL: magic variant, input shape, layer count, and size\n  \
- TFLite: embedding method, tensor names, tensor shapes, operation hints, and quantization markers\n  \
- ONNX: ModelProto graph name, input/output names, tensor shapes, producer, IR version, and op types\n  \
- Qualcomm DLC: container strings, source framework hints, quantization markers, and accelerator/runtime hints\n\n\
Evidence boundary:\n  \
- Runtime/library findings prove scanner evidence, not runtime reachability\n  \
- DLC corpus validation depends on a local .dlc artifact; no DLC sample is bundled\n  \
- JSON uses edge-ai-scan/v1 and includes finding metadata when available\n\n\
Examples:\n  \
fat edge-ai scan --rootfs ./rootfs\n  \
fat edge-ai scan --rootfs ./rootfs --format magik,tflite --json\n  \
fat edge-ai scan --rootfs ./rootfs --format onnx";

#[derive(Debug, Clone, Subcommand)]
pub enum EdgeAiCommand {
    #[command(
        about = "Scan an extracted rootfs for Edge AI models and inference runtimes.",
        long_about = EDGE_AI_SCAN_LONG_ABOUT
    )]
    Scan(EdgeAiScanArgs),
}

#[derive(Debug, Clone, Args)]
pub struct EdgeAiScanArgs {
    #[arg(
        long,
        help = "Directory to scan; can be an extracted rootfs or model corpus directory."
    )]
    rootfs: PathBuf,
    #[arg(
        long = "format",
        value_name = "FORMAT[,FORMAT...]",
        help = "Optional comma-separated filter: magik,tflite,onnx,dlc."
    )]
    format: Option<String>,
    #[arg(
        long,
        help = "Emit edge-ai-scan/v1 JSON including finding metadata when available."
    )]
    json: bool,
}

pub fn run(command: EdgeAiCommand) -> DynResult<()> {
    match command {
        EdgeAiCommand::Scan(args) => run_scan(args),
    }
}

fn run_scan(args: EdgeAiScanArgs) -> DynResult<()> {
    let formats = parse_formats(args.format.as_deref())?;
    let report = scan_edge_ai_root(&args.rootfs, &formats)?;

    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    let palette = crate::style::Palette::stdout();
    if !palette.enabled() {
        println!(
            "Edge AI scan: {} finding(s) under {}",
            report.finding_count, report.root
        );
        println!(
            "Formats: {}",
            report
                .formats
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        );

        for finding in &report.findings {
            let subject = match &finding.subject {
                FindingSubject::File { rel_path } => rel_path.as_str(),
                FindingSubject::Binary { binary_id } => binary_id.as_str(),
                FindingSubject::Bootloader { family } => family.as_str(),
                FindingSubject::Project => "project",
            };
            let plugin = finding.plugin_id.as_deref().unwrap_or("edge-ai");
            println!(
                "- [{:?}] {}: {} ({})",
                finding.severity, plugin, finding.title, subject
            );
        }
        return Ok(());
    }

    let mut lines = Vec::new();
    if report.findings.is_empty() {
        lines.push(format!(
            "{} {}",
            palette.dot_muted(),
            palette.muted("no models found")
        ));
    } else {
        lines.push(format!(
            "{} {} model(s) found",
            palette.dot_ok(),
            palette.good(report.finding_count.to_string())
        ));
    }
    lines.push(format!(
        "· {}",
        palette.muted(format!(
            "formats: {}",
            report
                .formats
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join(", ")
        ))
    ));

    for finding in &report.findings {
        let subject = match &finding.subject {
            FindingSubject::File { rel_path } => rel_path.as_str(),
            FindingSubject::Binary { binary_id } => binary_id.as_str(),
            FindingSubject::Bootloader { family } => family.as_str(),
            FindingSubject::Project => "project",
        };
        lines.push(format!(
            "{} {} {}",
            palette.dot_ok(),
            palette.severity_tag(&finding.severity),
            finding.title
        ));
        let mut detail = vec![subject.to_string()];
        if let Some(format) = finding.metadata.get("format") {
            detail.push(format!("format: {format}"));
        }
        lines.push(format!("· {}", palette.muted(detail.join(" · "))));
    }

    println!(
        "{}",
        palette.panel(&format!("fat edge-ai scan · {}", report.root), &lines)
    );
    if report.findings.is_empty() {
        println!(
            "{}",
            palette.next_hint(
                "models are detected in .bin/.so artifacts — re-run after `fat extract <project>`"
            )
        );
    }
    Ok(())
}

fn parse_formats(value: Option<&str>) -> DynResult<Vec<EdgeAiFormat>> {
    let Some(value) = value else {
        return Ok(Vec::new());
    };

    let mut formats = Vec::new();
    for raw_format in value.split(',') {
        let raw_format = raw_format.trim();
        if raw_format.is_empty() {
            continue;
        }

        let format = raw_format
            .parse::<EdgeAiFormat>()
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err))?;
        if !formats.contains(&format) {
            formats.push(format);
        }
    }

    Ok(formats)
}
