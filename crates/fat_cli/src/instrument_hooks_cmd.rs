use std::collections::{BTreeMap, HashMap, HashSet};
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use fat_taint::sink_discovery::{
    Confidence as SinkConfidence, SinkCandidate as SinkDiscoveryCandidate, SinkDiscoveryReport,
    SinkEvidence as SinkDiscoveryEvidence, SinkFamily,
};
use fat_taint::TaintFinding;

type DynResult<T> = Result<T, Box<dyn Error>>;

/// A resolved hook — sink found in the binary with a concrete address.
struct ResolvedHook {
    address: u64,
    name: String,
    dangerous_arg: u8,
    category: String,
    sym_type: String, // "import", "export", "taint-chain", "taint-resolved"
    sink_family_key: Option<String>,
    sink_evidence: Vec<SinkDiscoveryEvidence>,
    sink_limitations: Vec<String>,
}

// ---------------------------------------------------------------------------
// Catalog mode: fat instrument-hooks --file <binary>
// ---------------------------------------------------------------------------

pub fn run(
    binary: &Path,
    output: Option<&Path>,
    json: bool,
    categories: Option<&str>,
) -> DynResult<()> {
    let category_filter: Option<Vec<&str>> = categories.map(|c| c.split(',').collect());

    // Run rabin2 once — we need the import list both for profile auto-detect
    // and for hook address resolution.
    let rabin2_output = run_rabin2(binary)?;

    // Hook discovery reads the same core models as taint analysis. It used to
    // keep a third hand-maintained copy of the catalog, retained specifically
    // so vendor entries survived when a binary did not match a profile's
    // detect markers — which is the drift that made the duplication visible.
    let mut sink_lookup: BTreeMap<String, (u8, String)> = fat_taint::profile::core_sink_catalog()
        .into_iter()
        .map(|entry| (entry.name, (entry.dangerous_arg, entry.category)))
        .collect();

    // Apply category filter if --categories was provided.
    if let Some(ref filter) = category_filter {
        sink_lookup.retain(|_, (_, cat)| filter.contains(&cat.as_str()));
    }

    // Resolve hooks from the already-parsed rabin2 output.
    let resolved = resolve_symbols_from_parsed(&rabin2_output, &sink_lookup)?;

    let palette = crate::style::Palette::stderr();
    if resolved.is_empty() {
        if palette.enabled() {
            let lines = vec![
                format!(
                    "{} no matching sinks found in {}",
                    palette.dot_muted(),
                    binary.display()
                ),
                format!(
                    "· {}",
                    palette.muted(format!(
                        "searched {} sink functions from the catalog",
                        sink_lookup.len()
                    ))
                ),
            ];
            eprintln!("{}", palette.panel("fat instrument-hooks", &lines));
            eprintln!(
                "{}",
                palette.next_hint(&format!(
                    "drop --categories or check imports with `fat r2-triage --file {}`",
                    binary.display()
                ))
            );
        } else {
            eprintln!("No matching sinks found in {}", binary.display());
            eprintln!(
                "Searched for {} sink functions from the catalog",
                sink_lookup.len()
            );
        }
        if output.is_some() || json {
            write_hooks_output(binary, &resolved, output, json)?;
        }
        return Ok(());
    }

    if palette.enabled() {
        let mut tally: BTreeMap<&str, usize> = BTreeMap::new();
        for hook in &resolved {
            *tally.entry(hook.category.as_str()).or_default() += 1;
        }
        let categories = tally
            .iter()
            .map(|(cat, count)| format!("{cat} {count}"))
            .collect::<Vec<_>>()
            .join(" · ");
        let lines = vec![
            format!(
                "{} {} hookable sinks · {}",
                palette.dot_ok(),
                palette.good(resolved.len().to_string()),
                binary.display()
            ),
            format!("· {}", palette.muted(format!("categories: {categories}"))),
        ];
        eprintln!("{}", palette.panel("fat instrument-hooks", &lines));
        eprintln!(
            "{}",
            palette.next_hint("fat emulate <project> --instrument hooks.yaml")
        );
    } else {
        eprintln!(
            "Found {} hookable sinks in {}",
            resolved.len(),
            binary.display()
        );
    }
    write_hooks_output(binary, &resolved, output, json)
}

// ---------------------------------------------------------------------------
// Taint mode: fat instrument-hooks --from-taint <json>
// ---------------------------------------------------------------------------

/// Generate hooks from TaintFinding JSON (output of `fat taint --json`).
///
/// Walks each ChainStep, resolves addresses from the `location` field (hex
/// parse) or falls back to rabin2 function-name lookup against the step's
/// binary.
pub fn run_from_taint(taint_json: &Path, output: Option<&Path>, json: bool) -> DynResult<()> {
    let content = fs::read_to_string(taint_json)?;
    let findings: Vec<TaintFinding> = serde_json::from_str(&content)?;

    if findings.is_empty() {
        eprintln!("No taint findings in {}", taint_json.display());
        return Ok(());
    }

    eprintln!(
        "Processing {} taint finding(s) from {}",
        findings.len(),
        taint_json.display()
    );

    // Collect steps that need rabin2 resolution, grouped by binary to minimize
    // rabin2 invocations.
    let mut need_resolution: HashMap<String, Vec<String>> = HashMap::new();
    let mut hooks: Vec<ResolvedHook> = Vec::new();

    for finding in &findings {
        for step in &finding.chain {
            let func = step.function.clone();

            if let Some(address) = parse_hex_address(&step.location) {
                hooks.push(ResolvedHook {
                    address,
                    name: func,
                    dangerous_arg: catalog_dangerous_arg(&step.function),
                    category: catalog_category(&step.function),
                    sym_type: "taint-chain".to_string(),
                    sink_family_key: None,
                    sink_evidence: Vec::new(),
                    sink_limitations: Vec::new(),
                });
            } else {
                need_resolution
                    .entry(step.binary.clone())
                    .or_default()
                    .push(func);
            }
        }
    }

    // Resolve unresolved functions via rabin2 per-binary
    for (binary_name, functions) in &need_resolution {
        match find_binary(binary_name) {
            Some(ref path) => {
                hooks.extend(resolve_functions_by_name(path, functions)?);
            }
            None => {
                eprintln!(
                    "  warning: binary '{}' not found, skipping {} function(s)",
                    binary_name,
                    functions.len()
                );
            }
        }
    }

    // Deduplicate by (name, address) and sort
    let mut seen = HashSet::new();
    hooks.retain(|h| seen.insert((h.name.clone(), h.address)));
    hooks.sort_by_key(|h| h.address);

    // Report per-finding resolution
    for finding in &findings {
        let chain_funcs: Vec<&str> = finding.chain.iter().map(|s| s.function.as_str()).collect();
        let resolved_count = chain_funcs
            .iter()
            .filter(|f| hooks.iter().any(|h| h.name == **f))
            .count();
        eprintln!(
            "  {}: {} — {}/{} steps resolved",
            finding.id,
            finding.title,
            resolved_count,
            chain_funcs.len()
        );
    }

    if hooks.is_empty() {
        eprintln!("No hooks could be resolved from taint findings");
        if output.is_some() || json {
            let label = Path::new("taint-findings");
            write_hooks_output(label, &hooks, output, json)?;
        }
        return Ok(());
    }

    eprintln!(
        "Generated {} hook(s) from {} finding(s)",
        hooks.len(),
        findings.len()
    );
    let label = Path::new("taint-findings");
    write_hooks_output(label, &hooks, output, json)
}

/// Generate hooks from SinkDiscoveryReport JSON (output of `fat sink-discovery --json`).
///
/// Only candidates at probable confidence or above are considered. Weak or
/// addressless candidates are skipped because they are not strong enough to
/// drive instrumentation.
pub fn run_from_sinks(sinks_json: &Path, output: Option<&Path>, json: bool) -> DynResult<()> {
    let content = fs::read_to_string(sinks_json)?;
    let report: SinkDiscoveryReport = serde_json::from_str(&content)?;
    let report_file = PathBuf::from(report.file.clone());

    let mut hooks: Vec<ResolvedHook> = Vec::new();
    for candidate in report.candidates {
        if candidate.confidence < SinkConfidence::Probable {
            continue;
        }
        let Some(address) = candidate.address else {
            continue;
        };
        hooks.push(ResolvedHook {
            address,
            name: candidate
                .symbolic_name
                .clone()
                .unwrap_or_else(|| candidate_name(&candidate)),
            dangerous_arg: 0,
            category: canonical_category_for(&candidate),
            sym_type: "sink-discovery".to_string(),
            sink_family_key: Some(family_key_for(&candidate)),
            sink_evidence: candidate.evidence.clone(),
            sink_limitations: candidate.limitations.clone(),
        });
    }

    hooks.sort_by_key(|hook| hook.address);

    if hooks.is_empty() {
        eprintln!("No sink discovery candidates were eligible for hook generation");
    }

    write_hooks_output(&report_file, &hooks, output, json)
}

/// Try to parse a hex address from a freeform location string.
///
/// Handles: "0x00412a8c", "0x412a8c", "412a8c" (bare hex), and
/// "system at 0x00412a8c" (embedded hex).
fn parse_hex_address(location: &str) -> Option<u64> {
    let trimmed = location.trim();
    if trimmed.is_empty() {
        return None;
    }

    // "0x..." prefix
    if let Some(hex) = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
    {
        return u64::from_str_radix(hex, 16).ok();
    }

    // Bare hex (all hex digits, >= 4 chars to avoid matching short strings like "dead")
    if trimmed.len() >= 4 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return u64::from_str_radix(trimmed, 16).ok();
    }

    // Embedded "0x..." within descriptive text
    if let Some(pos) = trimmed.find("0x").or_else(|| trimmed.find("0X")) {
        let after = &trimmed[pos + 2..];
        let hex_part: String = after
            .chars()
            .take_while(|c| c.is_ascii_hexdigit())
            .collect();
        if !hex_part.is_empty() {
            return u64::from_str_radix(&hex_part, 16).ok();
        }
    }

    None
}

fn candidate_name(candidate: &SinkDiscoveryCandidate) -> String {
    if !candidate.id.trim().is_empty() {
        format!("candidate_{}", candidate.id)
    } else if let Some(address) = candidate.address {
        format!("candidate_0x{address:08x}")
    } else {
        "candidate_sink".to_string()
    }
}

fn family_key_for(candidate: &SinkDiscoveryCandidate) -> String {
    if !candidate.family_key.trim().is_empty() {
        candidate.family_key.clone()
    } else {
        match candidate.family {
            SinkFamily::CommandExec => "command-exec".to_string(),
            SinkFamily::ConfigRead => "config-read".to_string(),
            SinkFamily::ConfigWrite => "config-write".to_string(),
            SinkFamily::InputSource => "input-source".to_string(),
            SinkFamily::StringOverflow => "string-overflow".to_string(),
            SinkFamily::NetworkEgress => "network-egress".to_string(),
            SinkFamily::FileWrite => "file-write".to_string(),
            SinkFamily::Unknown => "unknown".to_string(),
        }
    }
}

fn canonical_category_for(candidate: &SinkDiscoveryCandidate) -> String {
    match candidate.family {
        SinkFamily::CommandExec => "command-exec".to_string(),
        SinkFamily::ConfigRead => "config-read".to_string(),
        SinkFamily::ConfigWrite => "config-write".to_string(),
        SinkFamily::InputSource => "input-source".to_string(),
        SinkFamily::StringOverflow => "string-overflow".to_string(),
        SinkFamily::NetworkEgress => "network-egress".to_string(),
        SinkFamily::FileWrite => "file-write".to_string(),
        SinkFamily::Unknown => family_key_for(candidate),
    }
}

/// Look up sink category from the static catalog, defaulting to "taint-chain".
fn catalog_category(function: &str) -> String {
    fat_taint::profile::core_sink_catalog()
        .into_iter()
        .find(|entry| entry.name == function)
        .map(|entry| entry.category)
        .unwrap_or_else(|| "taint-chain".to_string())
}

/// Look up the dangerous argument index from the static catalog, defaulting to 0.
fn catalog_dangerous_arg(function: &str) -> u8 {
    fat_taint::profile::core_sink_catalog()
        .into_iter()
        .find(|entry| entry.name == function)
        .map(|entry| entry.dangerous_arg)
        .unwrap_or(0)
}

/// Try to find a binary by name — as-is path, then stripped leading "/".
fn find_binary(binary_name: &str) -> Option<PathBuf> {
    let p = PathBuf::from(binary_name);
    if p.exists() {
        return Some(p);
    }
    if let Some(rel) = binary_name.strip_prefix('/') {
        let rel_path = PathBuf::from(rel);
        if rel_path.exists() {
            return Some(rel_path);
        }
    }
    None
}

/// Resolve function names to addresses in a binary using rabin2.
/// Fallback for ChainStep.location values that don't contain a parseable address.
fn resolve_functions_by_name(
    binary: &Path,
    function_names: &[String],
) -> DynResult<Vec<ResolvedHook>> {
    let output = Command::new("rabin2")
        .args(["-isj", binary.to_str().unwrap_or("")])
        .output()?;

    if !output.status.success() {
        eprintln!(
            "  warning: rabin2 failed for {}: {}",
            binary.display(),
            String::from_utf8_lossy(&output.stderr)
        );
        return Ok(Vec::new());
    }

    let json_str = String::from_utf8_lossy(&output.stdout);
    let parsed: serde_json::Value = serde_json::from_str(&json_str)?;

    let mut name_to_addr: HashMap<String, u64> = HashMap::new();

    if let Some(imports) = parsed.get("imports").and_then(|v| v.as_array()) {
        for imp in imports {
            let name = imp.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let vaddr = imp.get("vaddr").and_then(|v| v.as_u64()).unwrap_or(0);
            let plt = imp.get("plt").and_then(|v| v.as_u64()).unwrap_or(0);
            let addr = if vaddr != 0 { vaddr } else { plt };
            if addr != 0 {
                name_to_addr.insert(name.to_string(), addr);
            }
        }
    }

    if let Some(symbols) = parsed.get("symbols").and_then(|v| v.as_array()) {
        for sym in symbols {
            let name = sym.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let vaddr = sym.get("vaddr").and_then(|v| v.as_u64()).unwrap_or(0);
            if vaddr == 0 {
                continue;
            }
            let canonical = name.strip_prefix("imp.").unwrap_or(name);
            name_to_addr.entry(canonical.to_string()).or_insert(vaddr);
        }
    }

    let mut resolved = Vec::new();
    for func in function_names {
        if let Some(&addr) = name_to_addr.get(func.as_str()) {
            resolved.push(ResolvedHook {
                address: addr,
                name: func.clone(),
                dangerous_arg: catalog_dangerous_arg(func),
                category: catalog_category(func),
                sym_type: "taint-resolved".to_string(),
                sink_family_key: None,
                sink_evidence: Vec::new(),
                sink_limitations: Vec::new(),
            });
        } else {
            eprintln!(
                "  warning: function '{}' not found in {} via rabin2",
                func,
                binary.display()
            );
        }
    }

    Ok(resolved)
}

// ---------------------------------------------------------------------------
// Symbol resolution (catalog mode)
// ---------------------------------------------------------------------------

/// Run rabin2 once and return the parsed JSON.
fn run_rabin2(binary: &Path) -> DynResult<serde_json::Value> {
    let output = Command::new("rabin2")
        .args(["-isj", binary.to_str().unwrap_or("")])
        .output()?;

    if !output.status.success() {
        return Err(format!("rabin2 failed: {}", String::from_utf8_lossy(&output.stderr)).into());
    }

    let json_str = String::from_utf8_lossy(&output.stdout);
    Ok(serde_json::from_str(&json_str)?)
}

/// Resolve hooks from pre-parsed rabin2 JSON against a sink lookup table.
fn resolve_symbols_from_parsed(
    parsed: &serde_json::Value,
    sink_lookup: &BTreeMap<String, (u8, String)>,
) -> DynResult<Vec<ResolvedHook>> {
    let mut resolved = Vec::new();

    // Process imports — use PLT address if vaddr is 0
    if let Some(imports) = parsed.get("imports").and_then(|v| v.as_array()) {
        for imp in imports {
            let name = imp.get("name").and_then(|v| v.as_str()).unwrap_or("");

            // rabin2 puts the real PLT stub address in the "plt" field for MIPS
            let vaddr = imp.get("vaddr").and_then(|v| v.as_u64()).unwrap_or(0);
            let plt = imp.get("plt").and_then(|v| v.as_u64()).unwrap_or(0);
            let addr = if vaddr != 0 { vaddr } else { plt };

            if addr == 0 {
                continue;
            }

            if let Some((arg, cat)) = sink_lookup.get(name) {
                resolved.push(ResolvedHook {
                    address: addr,
                    name: name.to_string(),
                    dangerous_arg: *arg,
                    category: cat.to_string(),
                    sym_type: "import".to_string(),
                    sink_family_key: None,
                    sink_evidence: Vec::new(),
                    sink_limitations: Vec::new(),
                });
            }
        }
    }

    // Process symbols — handles MIPS PLT stubs ("imp.function_name")
    if let Some(symbols) = parsed.get("symbols").and_then(|v| v.as_array()) {
        let mut seen: HashSet<(String, u64)> = resolved
            .iter()
            .map(|h| (h.name.clone(), h.address))
            .collect();

        for sym in symbols {
            let name = sym.get("name").and_then(|v| v.as_str()).unwrap_or("");
            let vaddr = sym.get("vaddr").and_then(|v| v.as_u64()).unwrap_or(0);
            let sym_type = sym.get("type").and_then(|v| v.as_str()).unwrap_or("");

            if vaddr == 0 || sym_type == "NOTYPE" {
                continue;
            }

            let canonical = name.strip_prefix("imp.").unwrap_or(name);

            if !seen.insert((canonical.to_string(), vaddr)) {
                continue;
            }

            if let Some((arg, cat)) = sink_lookup.get(canonical) {
                resolved.push(ResolvedHook {
                    address: vaddr,
                    name: canonical.to_string(),
                    dangerous_arg: *arg,
                    category: cat.to_string(),
                    sym_type: if name.starts_with("imp.") {
                        "plt-stub".to_string()
                    } else {
                        "symbol".to_string()
                    },
                    sink_family_key: None,
                    sink_evidence: Vec::new(),
                    sink_limitations: Vec::new(),
                });
            }
        }
    }

    resolved.sort_by_key(|h| h.address);
    Ok(resolved)
}

// ---------------------------------------------------------------------------
// Output formatting
// ---------------------------------------------------------------------------

fn format_hooks_yaml(binary: &Path, hooks: &[ResolvedHook]) -> String {
    let mut out = String::new();
    out.push_str("# FAT Hook Plugin — auto-generated from taint sink analysis\n");
    out.push_str(&format!("# Binary: {}\n", binary.display()));
    out.push_str(&format!("# Generated hooks: {}\n", hooks.len()));
    out.push_str("#\n");
    out.push_str(
        "# Usage: qemu-system-mipsel ... -plugin fat-hook.so,config=hooks.yaml,log=trace.jsonl\n\n",
    );
    out.push_str("hooks:\n");

    for hook in hooks {
        out.push_str(&format!(
            "  - address: 0x{:08x}\n    name: {}\n",
            hook.address, hook.name
        ));

        let string_args = sink_string_args(hook);
        if !string_args.is_empty() {
            out.push_str(&format!("    string_args: [{}]\n", string_args.join(", ")));
        }

        out.push_str(&format!(
            "    # category: {} ({})\n",
            hook.category, hook.sym_type
        ));
    }

    out
}

fn sink_string_args(hook: &ResolvedHook) -> Vec<&'static str> {
    let reg = |idx: u8| -> &'static str {
        match idx {
            0 => "a0",
            1 => "a1",
            2 => "a2",
            3 => "a3",
            _ => "a0",
        }
    };

    match hook.category.as_str() {
        "command-exec" => vec![reg(hook.dangerous_arg)],
        "config-read" | "config-write" => vec![reg(hook.dangerous_arg)],
        "input-source" => vec![reg(hook.dangerous_arg)],
        "string-overflow" => vec![],
        // taint-chain functions not in catalog: trace a0 as best effort
        "taint-chain" => vec!["a0"],
        _ => vec![],
    }
}

fn format_json(hooks: &[ResolvedHook]) -> String {
    let entries: Vec<serde_json::Value> = hooks
        .iter()
        .map(|h| {
            let mut entry = serde_json::json!({
                "address": format!("0x{:08x}", h.address),
                "name": h.name,
                "dangerous_arg": h.dangerous_arg,
                "category": h.category,
                "sym_type": h.sym_type,
                "string_args": sink_string_args(h),
            });
            if !h.sink_evidence.is_empty() {
                entry["sink_evidence"] = serde_json::to_value(&h.sink_evidence).unwrap();
            }
            if let Some(family_key) = &h.sink_family_key {
                entry["sink_family_key"] = serde_json::Value::String(family_key.clone());
            }
            if !h.sink_limitations.is_empty() {
                entry["sink_limitations"] = serde_json::to_value(&h.sink_limitations).unwrap();
            }
            entry
        })
        .collect();

    serde_json::to_string_pretty(&serde_json::json!({ "hooks": entries })).unwrap()
}

/// Format resolved hooks and write to output path (or stdout).
/// Always writes, even when `hooks` is empty — callers depend on
/// the output file existing for batch processing.
fn write_hooks_output(
    binary: &Path,
    hooks: &[ResolvedHook],
    output: Option<&Path>,
    json: bool,
) -> DynResult<()> {
    let content = if json {
        format_json(hooks)
    } else {
        format_hooks_yaml(binary, hooks)
    };
    if let Some(out_path) = output {
        fs::write(out_path, &content)?;
        eprintln!("Wrote hooks config to {}", out_path.display());
    } else {
        print!("{content}");
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_hex_address_0x_prefix() {
        assert_eq!(parse_hex_address("0x00412a8c"), Some(0x00412a8c));
        assert_eq!(parse_hex_address("0X00412A8C"), Some(0x00412a8c));
    }

    #[test]
    fn parse_hex_address_bare_hex() {
        assert_eq!(parse_hex_address("00412a8c"), Some(0x00412a8c));
    }

    #[test]
    fn parse_hex_address_embedded() {
        assert_eq!(parse_hex_address("system at 0x00412a8c"), Some(0x00412a8c));
        assert_eq!(
            parse_hex_address("PLT stub 0x00413f10 for system"),
            Some(0x00413f10)
        );
    }

    #[test]
    fn parse_hex_address_empty_and_symbolic() {
        assert_eq!(parse_hex_address(""), None);
        assert_eq!(parse_hex_address("main"), None);
        assert_eq!(parse_hex_address("do_stuff"), None);
    }

    #[test]
    fn parse_hex_address_short_hex_rejected() {
        // 3-char hex should NOT be treated as an address
        assert_eq!(parse_hex_address("abc"), None);
    }

    #[test]
    fn catalog_lookup_known_function() {
        assert_eq!(catalog_category("system"), "command-exec");
        assert_eq!(catalog_dangerous_arg("system"), 0);
    }

    #[test]
    fn catalog_lookup_unknown_function() {
        assert_eq!(catalog_category("my_custom_func"), "taint-chain");
        assert_eq!(catalog_dangerous_arg("my_custom_func"), 0);
    }

    #[test]
    fn run_from_taint_parses_fixture() {
        let fixture = serde_json::json!([
            {
                "id": "T-001",
                "title": "cgibin_get_var -> system",
                "severity": "High",
                "chain": [
                    {
                        "binary": "/usr/sbin/httpd",
                        "function": "cgibin_get_var",
                        "location": "0x00412a8c",
                        "action": "reads HTTP parameter",
                        "edge_type": "DirectFlow"
                    },
                    {
                        "binary": "/usr/sbin/httpd",
                        "function": "sprintf",
                        "location": "0x00413e44",
                        "action": "formats string with unsanitized input",
                        "edge_type": "DirectFlow"
                    },
                    {
                        "binary": "/usr/sbin/httpd",
                        "function": "system",
                        "location": "0x00413f10",
                        "action": "executes shell command",
                        "edge_type": "DirectFlow"
                    }
                ],
                "status": "Proven",
                "status_reason": "all edges DirectFlow",
                "confidence": 0.95,
                "source_class": "Primary"
            }
        ]);

        let dir = tempfile::tempdir().unwrap();
        let taint_path = dir.path().join("taint.json");
        fs::write(&taint_path, serde_json::to_string(&fixture).unwrap()).unwrap();

        let out_path = dir.path().join("hooks.yaml");
        run_from_taint(&taint_path, Some(&out_path), false).unwrap();

        assert!(out_path.exists(), "hooks.yaml should be created");
        let content = fs::read_to_string(&out_path).unwrap();

        // All three chain steps should produce hooks
        assert!(
            content.contains("cgibin_get_var"),
            "should contain source function"
        );
        assert!(content.contains("sprintf"), "should contain hop function");
        assert!(content.contains("system"), "should contain sink function");

        // Addresses should be preserved from location fields
        assert!(content.contains("0x00412a8c"), "source address");
        assert!(content.contains("0x00413e44"), "hop address");
        assert!(content.contains("0x00413f10"), "sink address");
    }

    #[test]
    fn run_from_taint_json_output() {
        let fixture = serde_json::json!([
            {
                "id": "T-002",
                "title": "getenv -> strcpy",
                "severity": "Medium",
                "chain": [
                    {
                        "binary": "/usr/sbin/httpd",
                        "function": "getenv",
                        "location": "0x00401000",
                        "action": "reads env var",
                        "edge_type": "DirectFlow"
                    },
                    {
                        "binary": "/usr/sbin/httpd",
                        "function": "strcpy",
                        "location": "0x00401100",
                        "action": "copies without bounds",
                        "edge_type": "DirectFlow"
                    }
                ],
                "status": "Proven",
                "status_reason": "",
                "confidence": 0.95,
                "source_class": "Primary"
            }
        ]);

        let dir = tempfile::tempdir().unwrap();
        let taint_path = dir.path().join("taint.json");
        fs::write(&taint_path, serde_json::to_string(&fixture).unwrap()).unwrap();

        let out_path = dir.path().join("hooks.json");
        run_from_taint(&taint_path, Some(&out_path), true).unwrap();

        let content: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&out_path).unwrap()).unwrap();
        let hooks = content["hooks"].as_array().unwrap();
        assert_eq!(hooks.len(), 2);
        assert_eq!(hooks[0]["name"], "getenv");
        assert_eq!(hooks[1]["name"], "strcpy");
    }

    #[test]
    fn run_from_sinks_writes_probable_command_exec_hook_yaml() {
        let report = fat_taint::sink_discovery::SinkDiscoveryReport {
            file: "./bin/httpd".into(),
            binary: fat_taint::sink_discovery::BinaryContext {
                format: "ELF".into(),
                arch: "mips".into(),
                bits: 32,
                endianness: "little".into(),
                class: "ELF32".into(),
                stripped: Some(true),
            },
            profiles: vec!["linux-command-exec".into()],
            summary: fat_taint::sink_discovery::SinkDiscoverySummary::default(),
            candidates: vec![fat_taint::sink_discovery::SinkCandidate {
                id: "sink-0".into(),
                family: fat_taint::sink_discovery::SinkFamily::CommandExec,
                family_key: "command-exec".into(),
                address: Some(0x00413f10),
                symbolic_name: Some("candidate_system".into()),
                confidence: fat_taint::sink_discovery::Confidence::Probable,
                score: 0.82,
                providers: vec!["string_ref".into(), "pointer_xref".into()],
                evidence: vec![
                    fat_taint::sink_discovery::SinkEvidence::StringRef {
                        profile: "linux-command-exec".into(),
                        rule: "string_seeds:/bin/sh".into(),
                        value: "/bin/sh".into(),
                        vaddr: 0x004f2ed0,
                        score_delta: 0.35,
                    },
                    fat_taint::sink_discovery::SinkEvidence::PointerXref {
                        profile: "linux-command-exec".into(),
                        rule: "pointer_xrefs".into(),
                        pointer_vaddr: 0x004f8a10,
                        points_to: 0x004f2ed0,
                        score_delta: 0.20,
                    },
                ],
                limitations: vec!["function context not proven".into()],
            }],
        };

        let dir = tempfile::tempdir().unwrap();
        let sinks_path = dir.path().join("sinks.json");
        let out_path = dir.path().join("hooks.yaml");
        fs::write(&sinks_path, serde_json::to_string_pretty(&report).unwrap()).unwrap();

        run_from_sinks(&sinks_path, Some(&out_path), false).unwrap();

        let content = fs::read_to_string(&out_path).unwrap();
        assert!(content.contains("candidate_system"), "{content}");
        assert!(content.contains("0x00413f10"), "{content}");
    }

    #[test]
    fn run_from_sinks_preserves_canonical_categories_in_json() {
        let report = serde_json::json!({
            "file": "./bin/httpd",
            "binary": {
                "format": "ELF",
                "arch": "mips",
                "bits": 32,
                "endianness": "little",
                "class": "ELF32"
            },
            "summary": {"candidates": 2},
            "candidates": [
                {
                    "id": "sink-0",
                    "family": "command-exec",
                    "family_key": "vendor-shell-wrapper",
                    "address": "0x00413f10",
                    "confidence": "probable",
                    "score": 0.55
                },
                {
                    "id": "sink-1",
                    "family": "config-read",
                    "family_key": "config-read",
                    "address": "0x00415000",
                    "confidence": "probable",
                    "score": 0.55
                }
            ]
        });

        let dir = tempfile::tempdir().unwrap();
        let sinks_path = dir.path().join("sinks.json");
        let out_path = dir.path().join("hooks.json");
        fs::write(&sinks_path, serde_json::to_string_pretty(&report).unwrap()).unwrap();

        run_from_sinks(&sinks_path, Some(&out_path), true).unwrap();

        let content: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&out_path).unwrap()).unwrap();
        let hooks = content["hooks"].as_array().unwrap();
        assert_eq!(hooks.len(), 2);
        assert_eq!(hooks[0]["category"], "command-exec");
        assert_eq!(hooks[0]["sink_family_key"], "vendor-shell-wrapper");
        assert_eq!(hooks[0]["string_args"], serde_json::json!(["a0"]));
        assert_eq!(hooks[1]["category"], "config-read");
        assert_eq!(hooks[1]["string_args"], serde_json::json!(["a0"]));
    }

    #[test]
    fn run_from_taint_symbolic_locations_skipped_gracefully() {
        // Symbolic locations without hex addresses and with non-existent binaries
        // should produce warnings but not fail
        let fixture = serde_json::json!([
            {
                "id": "T-003",
                "title": "symbolic chain",
                "severity": "Low",
                "chain": [
                    {
                        "binary": "/nonexistent/binary",
                        "function": "some_func",
                        "location": "somewhere in main",
                        "action": "does something",
                        "edge_type": "DirectFlow"
                    }
                ],
                "status": "Candidate",
                "status_reason": "",
                "confidence": 0.4,
                "source_class": "Primary"
            }
        ]);

        let dir = tempfile::tempdir().unwrap();
        let taint_path = dir.path().join("taint.json");
        fs::write(&taint_path, serde_json::to_string(&fixture).unwrap()).unwrap();

        // Should not error — graceful degradation
        let result = run_from_taint(&taint_path, None, false);
        assert!(result.is_ok());
    }

    #[test]
    fn write_hooks_output_json_empty() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("hooks.json");
        write_hooks_output(Path::new("/tmp/test"), &[], Some(&out), true).unwrap();
        assert!(
            out.exists(),
            "output file must be created even with no hooks"
        );
        let content: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(content["hooks"], serde_json::json!([]));
    }

    #[test]
    fn write_hooks_output_yaml_empty() {
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("hooks.yaml");
        write_hooks_output(Path::new("/tmp/test"), &[], Some(&out), false).unwrap();
        assert!(
            out.exists(),
            "output file must be created even with no hooks"
        );
        let content = fs::read_to_string(&out).unwrap();
        assert!(content.contains("hooks:"), "YAML must contain hooks key");
    }

    #[test]
    fn write_hooks_output_json_with_hooks() {
        let hooks = vec![ResolvedHook {
            address: 0x00401000,
            name: "system".to_string(),
            dangerous_arg: 0,
            category: "command-exec".to_string(),
            sym_type: "import".to_string(),
            sink_family_key: None,
            sink_evidence: Vec::new(),
            sink_limitations: Vec::new(),
        }];
        let dir = tempfile::tempdir().unwrap();
        let out = dir.path().join("hooks.json");
        write_hooks_output(Path::new("/tmp/test"), &hooks, Some(&out), true).unwrap();
        let content: serde_json::Value =
            serde_json::from_str(&fs::read_to_string(&out).unwrap()).unwrap();
        assert_eq!(content["hooks"].as_array().unwrap().len(), 1);
    }
}
