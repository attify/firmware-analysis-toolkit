use regex::Regex;
use serde::Serialize;
use std::collections::BTreeMap;
use std::error::Error;
use std::path::Path;

type DynResult<T> = Result<T, Box<dyn Error>>;

const SCHEMA: &str = "bootloader-handoff/v1";
const DEFAULT_LANDMARKS: &[&str] = &[
    "Starting kernel",
    "Booting Linux",
    "Jumping to entry",
    "## Booting",
];

#[derive(Debug, Serialize)]
pub(crate) struct BootloaderHandoffReport {
    schema: &'static str,
    status: String,
    input: HandoffInputReport,
    candidates: Vec<HandoffCandidateReport>,
    integrity_vocab: IntegrityVocabularyReport,
    proves: Vec<String>,
    does_not_prove: Vec<String>,
}

#[derive(Debug, Serialize)]
struct HandoffInputReport {
    file: String,
    mode: String,
    arch: String,
    base: String,
    landmarks: Vec<String>,
    function: Option<String>,
    decompile_file: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct HandoffCandidateReport {
    rank: usize,
    confidence: String,
    confidence_reasons: Vec<String>,
    function: FunctionCandidateReport,
    landmark: Option<LandmarkReport>,
    transform: TransformReport,
    call: CallReport,
    evidence_window: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
struct FunctionCandidateReport {
    address: Option<String>,
    name: Option<String>,
    boundary: String,
}

#[derive(Debug, Clone, Serialize)]
struct LandmarkReport {
    string: String,
    file_offset: String,
    vaddr: String,
    code_hit: Option<String>,
    pattern: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct TransformReport {
    kind: String,
    expression: String,
    source_symbol: Option<String>,
    source_assignment: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
struct CallReport {
    #[serde(rename = "type")]
    kind: String,
    callsite_addr: Option<String>,
    decompile_line: usize,
    target_expression: String,
    arguments_excerpt: Option<String>,
}

#[derive(Debug, Serialize)]
struct IntegrityVocabularyReport {
    scope: String,
    terms: Vec<String>,
    matches: Vec<String>,
    claim: String,
}

#[derive(Debug, Clone)]
struct FunctionSource {
    address: Option<u64>,
    name: Option<String>,
    landmark: Option<LandmarkSource>,
}

#[derive(Debug, Clone)]
struct LandmarkSource {
    string: String,
    vaddr: u64,
    instruction_vaddr: Option<u64>,
    pattern: Option<String>,
}

#[derive(Debug, Clone)]
struct TextHandoffMatch {
    decompile_line: usize,
    expression: String,
    source_symbol: Option<String>,
    source_assignment: Option<String>,
    target_expression: String,
    arguments_excerpt: Option<String>,
    evidence_window: Vec<String>,
}

pub(crate) fn run(
    file: &Path,
    raw: bool,
    arch: Option<&str>,
    base: Option<&str>,
    landmarks: &[String],
    function: Option<&str>,
    decompile_file: Option<&Path>,
    json: bool,
) -> DynResult<()> {
    let landmark_set = if landmarks.is_empty() {
        DEFAULT_LANDMARKS
            .iter()
            .map(|landmark| (*landmark).to_string())
            .collect::<Vec<_>>()
    } else {
        landmarks.to_vec()
    };
    let arch = arch.unwrap_or("mips-pic");
    let base_value = base
        .map(crate::raw_mips_pic::parse_hex_value)
        .transpose()?
        .unwrap_or(0);
    let input = HandoffInputReport {
        file: file.display().to_string(),
        mode: if raw {
            "raw".into()
        } else {
            "unsupported".into()
        },
        arch: arch.to_string(),
        base: format!("0x{base_value:08x}"),
        landmarks: landmark_set.clone(),
        function: function.map(|value| value.to_string()),
        decompile_file: decompile_file.map(|path| path.display().to_string()),
    };

    let bytes = std::fs::read(file)?;
    let integrity_vocab = scan_integrity_vocab(&bytes);

    if !raw || (!arch.eq_ignore_ascii_case("mips-pic") && !arch.eq_ignore_ascii_case("mips")) {
        let report = BootloaderHandoffReport {
            schema: SCHEMA,
            status: "unsupported".to_string(),
            input,
            candidates: Vec::new(),
            integrity_vocab,
            proves: proves_for_status("unsupported"),
            does_not_prove: does_not_prove(),
        };
        emit_report(&report, json)?;
        return Ok(());
    }

    let mut sources = discover_function_sources(&bytes, arch, base_value, &landmark_set, function)?;
    if sources.is_empty() && decompile_file.is_some() {
        sources.push(FunctionSource {
            address: None,
            name: None,
            landmark: None,
        });
    }

    let mut candidates = Vec::new();
    for source in &sources {
        let text = if let Some(path) = decompile_file {
            std::fs::read_to_string(path)?
        } else {
            let Some(address) = source.address else {
                continue;
            };
            let decompile_arch = if arch.eq_ignore_ascii_case("mips-pic") {
                "mips"
            } else {
                arch
            };
            crate::decompile_cmd::raw_decompile_to_string(
                file,
                &format!("0x{address:08x}"),
                Some(decompile_arch),
                base,
                None,
                1,
            )?
        };
        for detected in detect_handoff_matches(&text) {
            candidates.push(candidate_from_match(source, detected));
        }
    }

    candidates.sort_by(|left, right| {
        confidence_rank(&right.confidence)
            .cmp(&confidence_rank(&left.confidence))
            .then_with(|| {
                left.function
                    .address
                    .cmp(&right.function.address)
                    .then(left.call.decompile_line.cmp(&right.call.decompile_line))
            })
    });
    for (index, candidate) in candidates.iter_mut().enumerate() {
        candidate.rank = index + 1;
    }

    let status = match candidates.len() {
        0 => "no_match",
        1 => "candidate",
        _ => "ambiguous",
    }
    .to_string();

    let report = BootloaderHandoffReport {
        schema: SCHEMA,
        status: status.clone(),
        input,
        candidates,
        integrity_vocab,
        proves: proves_for_status(&status),
        does_not_prove: does_not_prove(),
    };
    emit_report(&report, json)?;
    Ok(())
}

fn discover_function_sources(
    bytes: &[u8],
    arch: &str,
    base: u64,
    landmarks: &[String],
    function: Option<&str>,
) -> DynResult<Vec<FunctionSource>> {
    if let Some(raw) = function {
        let address = crate::raw_mips_pic::parse_hex_value(raw)?;
        return Ok(vec![FunctionSource {
            address: Some(address),
            name: Some(format!("candidate_mips_pic_0x{address:08x}")),
            landmark: None,
        }]);
    }

    let mut by_function = BTreeMap::<u64, FunctionSource>::new();
    for landmark in landmarks {
        let targets = crate::raw_mips_pic::search_targets(bytes, arch, base, None, Some(landmark))?;
        for target in targets {
            for hit in target.code_hits {
                let Some(function_vaddr) = hit.function_vaddr else {
                    continue;
                };
                by_function.entry(function_vaddr).or_insert(FunctionSource {
                    address: Some(function_vaddr),
                    name: hit
                        .function_name
                        .clone()
                        .or_else(|| Some(format!("candidate_mips_pic_0x{function_vaddr:08x}"))),
                    landmark: Some(LandmarkSource {
                        string: landmark.clone(),
                        vaddr: target.vaddr,
                        instruction_vaddr: Some(hit.instruction_vaddr),
                        pattern: Some(hit.pattern.clone()),
                    }),
                });
            }
        }
    }
    Ok(by_function.into_values().collect())
}

fn detect_handoff_matches(text: &str) -> Vec<TextHandoffMatch> {
    let lines = text
        .lines()
        .map(|line| line.to_string())
        .collect::<Vec<_>>();
    let source_regex = Regex::new(r"([A-Za-z_][A-Za-z0-9_]*)\s*>>\s*0x18").ok();
    let mut matches = Vec::new();

    for index in 0..lines.len() {
        if !lines[index].contains(">> 0x18") || !lines[index].contains("<< 0x18") {
            continue;
        }
        let end = usize::min(index + 4, lines.len());
        let expression = lines[index..end].join(" ");
        if !looks_like_bswap32(&expression) || !looks_like_indirect_call(&expression) {
            continue;
        }
        let source_symbol = source_regex
            .as_ref()
            .and_then(|regex| regex.captures(&expression))
            .and_then(|captures| captures.get(1))
            .map(|symbol| symbol.as_str().to_string());
        let source_assignment = source_symbol
            .as_deref()
            .and_then(|symbol| find_source_assignment(&lines, index, symbol));
        let window_start = index.saturating_sub(2);
        let window_end = usize::min(index + 4, lines.len());
        matches.push(TextHandoffMatch {
            decompile_line: index + 1,
            expression: expression.trim().to_string(),
            source_symbol,
            source_assignment,
            target_expression: extract_target_expression(&expression),
            arguments_excerpt: extract_arguments_excerpt(&expression),
            evidence_window: lines[window_start..window_end]
                .iter()
                .map(|line| line.trim_end().to_string())
                .collect(),
        });
    }

    matches
}

fn looks_like_bswap32(expression: &str) -> bool {
    expression.contains(">> 0x18")
        && expression.contains("<< 0x18")
        && expression.contains("0xff00")
        && (expression.contains(">> 8") || expression.contains(">>0x8"))
}

fn looks_like_indirect_call(expression: &str) -> bool {
    let compact = expression.split_whitespace().collect::<String>();
    compact.contains("(*(") && compact.contains("))(")
}

fn find_source_assignment(lines: &[String], index: usize, symbol: &str) -> Option<String> {
    let start = index.saturating_sub(20);
    lines[start..index]
        .iter()
        .rev()
        .find(|line| line.contains(&format!("{symbol} =")))
        .map(|line| line.trim().to_string())
}

fn extract_target_expression(expression: &str) -> String {
    let compact = expression.trim();
    if let Some(end) = compact.find("))(") {
        return compact[..end + 2].trim().to_string();
    }
    if let Some(end) = compact.find("))") {
        return compact[..end + 2].trim().to_string();
    }
    compact.to_string()
}

fn extract_arguments_excerpt(expression: &str) -> Option<String> {
    let start = expression.find("))")?;
    let args = expression[start + 2..].trim();
    Some(args.chars().take(160).collect())
}

fn candidate_from_match(
    source: &FunctionSource,
    detected: TextHandoffMatch,
) -> HandoffCandidateReport {
    let has_landmark = source.landmark.is_some();
    let confidence = if has_landmark { "high" } else { "medium" };
    let mut confidence_reasons =
        vec!["bswap32-like shift/mask transform is used as an indirect-call target".to_string()];
    if has_landmark {
        confidence_reasons.push("function candidate is linked to a boot landmark xref".to_string());
    } else {
        confidence_reasons
            .push("no landmark xref was available for this decompile scope".to_string());
    }

    HandoffCandidateReport {
        rank: 0,
        confidence: confidence.to_string(),
        confidence_reasons,
        function: FunctionCandidateReport {
            address: source.address.map(|address| format!("0x{address:08x}")),
            name: source.name.clone(),
            boundary: "candidate_not_proven".to_string(),
        },
        landmark: source.landmark.as_ref().map(|landmark| LandmarkReport {
            string: landmark.string.clone(),
            file_offset: format!("0x{:08x}", landmark.vaddr),
            vaddr: format!("0x{:08x}", landmark.vaddr),
            code_hit: landmark
                .instruction_vaddr
                .map(|address| format!("0x{address:08x}")),
            pattern: landmark.pattern.clone(),
        }),
        transform: TransformReport {
            kind: "bswap32".to_string(),
            expression: detected.expression,
            source_symbol: detected.source_symbol,
            source_assignment: detected.source_assignment,
        },
        call: CallReport {
            kind: "indirect".to_string(),
            callsite_addr: None,
            decompile_line: detected.decompile_line,
            target_expression: detected.target_expression,
            arguments_excerpt: detected.arguments_excerpt,
        },
        evidence_window: detected.evidence_window,
    }
}

fn scan_integrity_vocab(bytes: &[u8]) -> IntegrityVocabularyReport {
    let scope = String::from_utf8_lossy(bytes).to_ascii_lowercase();
    let terms = ["rsa", "sha", "hmac", "signature", "verify", "ecdsa"];
    let matches = terms
        .iter()
        .filter(|term| scope.contains(**term))
        .map(|term| (*term).to_string())
        .collect::<Vec<_>>();
    let claim = if matches.is_empty() {
        "no common integrity terms observed in scanned scope; this is not evidence that secure boot is absent"
            .to_string()
    } else {
        "common integrity vocabulary observed in scanned scope; this is only a string-level signal"
            .to_string()
    };

    IntegrityVocabularyReport {
        scope: "input_file_ascii_lowercase".to_string(),
        terms: terms.iter().map(|term| (*term).to_string()).collect(),
        matches,
        claim,
    }
}

fn confidence_rank(confidence: &str) -> u8 {
    match confidence {
        "high" => 3,
        "medium" => 2,
        "low" => 1,
        _ => 0,
    }
}

fn proves_for_status(status: &str) -> Vec<String> {
    match status {
        "candidate" | "ambiguous" => vec![
            "A raw bootloader function candidate references a boot landmark string.".to_string(),
            "The candidate decompile contains a bswap32-like transform feeding an indirect call."
                .to_string(),
            "The report identifies a bounded static kernel-handoff candidate for follow-up."
                .to_string(),
        ],
        "no_match" => vec![
            "The requested raw blob, landmark scope, and decompile scope were scanned.".to_string(),
            "No bswap32-to-indirect-call handoff candidate was matched in that bounded scope."
                .to_string(),
        ],
        "unsupported" => vec![
            "The command recognized the request but did not analyze it because the input mode or architecture is unsupported in v1."
                .to_string(),
        ],
        _ => Vec::new(),
    }
}

fn does_not_prove() -> Vec<String> {
    vec![
        "It does not prove runtime boot succeeds on a device.".to_string(),
        "It does not prove the device accepts modified firmware.".to_string(),
        "It does not prove exploitability or bypass of secure boot.".to_string(),
        "It does not prove exact function boundaries or that every handoff path was found."
            .to_string(),
    ]
}

fn emit_report(report: &BootloaderHandoffReport, json: bool) -> DynResult<()> {
    if json {
        println!("{}", serde_json::to_string_pretty(report)?);
    } else {
        print!("{}", render_report(report));
    }
    Ok(())
}

fn render_report(report: &BootloaderHandoffReport) -> String {
    let mut out = String::new();
    out.push_str(&format!("bootloader handoff: {}\n", report.input.file));
    out.push_str(&format!(
        "status: {} | arch: {} | base: {}\n\n",
        report.status, report.input.arch, report.input.base
    ));
    if report.candidates.is_empty() {
        out.push_str("no handoff candidates matched\n");
    } else {
        out.push_str(
            "rank  confidence  function                      landmark         code_hit    transform  call      line\n",
        );
        for candidate in &report.candidates {
            let function = candidate
                .function
                .name
                .as_deref()
                .or(candidate.function.address.as_deref())
                .unwrap_or("unknown");
            let landmark = candidate
                .landmark
                .as_ref()
                .map(|landmark| landmark.string.as_str())
                .unwrap_or("-");
            let code_hit = candidate
                .landmark
                .as_ref()
                .and_then(|landmark| landmark.code_hit.as_deref())
                .unwrap_or("-");
            out.push_str(&format!(
                "{:<4}  {:<10}  {:<28}  {:<15}  {:<10}  {:<9}  {:<8}  {}\n",
                candidate.rank,
                candidate.confidence,
                function,
                landmark,
                code_hit,
                candidate.transform.kind,
                candidate.call.kind,
                candidate.call.decompile_line
            ));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detector_finds_tapo_shaped_bswap_indirect_call() {
        let text = r#"
  (*(uVar17 >> 0x18 | uVar17 << 0x18 | (uVar17 & 0xff00) << 8 |
      uVar17 >> 8 & 0xff00U))(arg0,arg1);
"#;
        let matches = detect_handoff_matches(text);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].source_symbol.as_deref(), Some("uVar17"));
    }

    #[test]
    fn detector_rejects_bswap_without_indirect_call() {
        let text = "uVar17 >> 0x18 | uVar17 << 0x18 | (uVar17 & 0xff00) << 8 | uVar17 >> 8;";
        assert!(detect_handoff_matches(text).is_empty());
    }

    #[test]
    fn detector_reports_multiple_handoff_shapes() {
        let text = r#"
  (*(uVar1 >> 0x18 | uVar1 << 0x18 | (uVar1 & 0xff00) << 8 | uVar1 >> 8 & 0xff00U))(a);
  (*(uVar2 >> 0x18 | uVar2 << 0x18 | (uVar2 & 0xff00) << 8 | uVar2 >> 8 & 0xff00U))(b);
"#;
        assert_eq!(detect_handoff_matches(text).len(), 2);
    }
}
