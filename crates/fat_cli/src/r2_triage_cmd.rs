//! `fat r2-triage` — one-command binary audit triage using radare2.
//!
//! Drives rabin2/r2 via the recon module in fat_taint, then produces a structured
//! report highlighting security-relevant surfaces: dangerous imports, auth-related
//! exports, classified strings, crypto libraries, and complexity-ranked functions.

use crate::style::{Palette, PipelineProgress};
use fat_analyze::loader::{resolve_loader_hints, LoaderHints};
use fat_taint::recon::r2::{self, BinaryString, Export, FunctionInfo, Import};
use serde::Serialize;
use std::collections::HashMap;
use std::error::Error;
use std::path::Path;

type DynResult<T> = Result<T, Box<dyn Error>>;

/// Panel-mode cap for list-like sections (imports, exports, strings, …).
/// `--full` disables capping; plain piped output is never capped.
const PANEL_CAP: usize = 12;

// ── Constants ───────────────────────────────────────────────────────────────

const DANGEROUS_FUNCTIONS: &[&str] = &[
    "strcpy", "sprintf", "strcat", "gets", "system", "popen", "memcpy", "sscanf",
];

const SECURITY_PATTERNS: &[&str] = &[
    "auth", "login", "session", "encrypt", "decrypt", "key", "password", "aes", "rsa", "random",
    "token",
];

const CRYPTO_LIBRARIES: &[&str] = &[
    "libssl",
    "libcrypto",
    "libmbedtls",
    "libwolfssl",
    "libgcrypt",
];

// ── Report structures ───────────────────────────────────────────────────────

#[derive(Debug, Serialize)]
struct TriageReport {
    profile: ProfileReport,
    dangerous_imports: Vec<String>,
    security_exports: Vec<String>,
    module_prefixes: Vec<ModulePrefix>,
    classified_strings: ClassifiedStrings,
    crypto_libraries: Vec<String>,
    top_complex_functions: Vec<FunctionReport>,
    total_functions: usize,
}

#[derive(Debug, Serialize)]
struct ProfileReport {
    arch: String,
    bits: u32,
    compiler: String,
    canary: bool,
    nx: bool,
    relro: String,
    stripped: bool,
    class: String,
    family: Option<String>,
    raw_blob: bool,
}

#[derive(Debug, Serialize)]
struct ModulePrefix {
    prefix: String,
    count: usize,
}

#[derive(Debug, Serialize)]
struct ClassifiedStrings {
    ip_addresses: Vec<StringEntry>,
    hostnames: Vec<StringEntry>,
    urls: Vec<StringEntry>,
    potential_secrets: Vec<StringEntry>,
    human_readable_messages: Vec<StringEntry>,
}

#[derive(Debug, Serialize)]
struct StringEntry {
    value: String,
    address: u64,
}

#[derive(Debug, Serialize)]
struct FunctionReport {
    name: String,
    address: u64,
    size: u64,
    basic_blocks: u64,
    cyclomatic_complexity: u64,
}

// ── Classification / filtering logic (pure, testable) ───────────────────────

fn filter_dangerous_imports(imports: &[Import]) -> Vec<String> {
    imports
        .iter()
        .filter(|i| DANGEROUS_FUNCTIONS.contains(&i.name.as_str()))
        .map(|i| i.name.clone())
        .collect()
}

fn filter_security_exports(exports: &[Export]) -> Vec<String> {
    exports
        .iter()
        .filter(|e| {
            let lower = demangle_cpp_symbol(&e.name).to_ascii_lowercase();
            SECURITY_PATTERNS.iter().any(|p| lower.contains(p))
        })
        .map(|e| demangle_cpp_symbol(&e.name))
        .collect()
}

fn group_by_module_prefix(exports: &[Export]) -> Vec<ModulePrefix> {
    let mut counts: HashMap<String, usize> = HashMap::new();
    for export in exports {
        let prefix = module_prefix_for_symbol(&export.name);
        *counts.entry(prefix).or_insert(0) += 1;
    }
    let mut prefixes: Vec<ModulePrefix> = counts
        .into_iter()
        .map(|(prefix, count)| ModulePrefix { prefix, count })
        .collect();
    prefixes.sort_by_key(|prefix| std::cmp::Reverse(prefix.count));
    prefixes
}

fn module_prefix_for_symbol(name: &str) -> String {
    let display_name = demangle_cpp_symbol(name);
    if display_name != name {
        if let Some(prefix) = display_name.split("::").next() {
            return prefix.to_string();
        }
    }
    name.split('_').next().unwrap_or(name).to_string()
}

pub(crate) fn demangle_cpp_symbol(name: &str) -> String {
    parse_itanium_cpp_symbol(name).unwrap_or_else(|| name.to_string())
}

fn parse_itanium_cpp_symbol(name: &str) -> Option<String> {
    let body = name.strip_prefix("_Z")?;
    let nested = body.strip_prefix('N')?;
    parse_itanium_nested_name(nested)
}

fn parse_itanium_nested_name(nested: &str) -> Option<String> {
    let mut idx = 0;
    let mut is_const_method = false;
    if nested.as_bytes().get(idx) == Some(&b'K') {
        is_const_method = true;
        idx += 1;
    }

    let mut components: Vec<String> = Vec::new();
    while idx < nested.len() && nested.as_bytes()[idx] != b'E' {
        let current = nested.as_bytes()[idx];
        if current == b'C'
            && idx + 1 < nested.len()
            && matches!(nested.as_bytes()[idx + 1], b'1' | b'2' | b'3')
        {
            components.push(components.last()?.clone());
            idx += 2;
            continue;
        }
        if current == b'D'
            && idx + 1 < nested.len()
            && matches!(nested.as_bytes()[idx + 1], b'0' | b'1' | b'2')
        {
            components.push(format!("~{}", components.last()?));
            idx += 2;
            continue;
        }
        if current == b'B' && idx + 1 < nested.len() && nested.as_bytes()[idx + 1].is_ascii_digit()
        {
            idx += 1;
            let start = idx;
            while idx < nested.len() && nested.as_bytes()[idx].is_ascii_digit() {
                idx += 1;
            }
            let len = nested[start..idx].parse::<usize>().ok()?;
            idx = idx.checked_add(len)?;
            if idx > nested.len() {
                return None;
            }
            continue;
        }

        let start = idx;
        while idx < nested.len() && nested.as_bytes()[idx].is_ascii_digit() {
            idx += 1;
        }
        if start == idx {
            return None;
        }
        let len = nested[start..idx].parse::<usize>().ok()?;
        let end = idx.checked_add(len)?;
        if end > nested.len() {
            return None;
        }
        components.push(nested[idx..end].to_string());
        idx = end;
    }

    if components.is_empty() || nested.as_bytes().get(idx) != Some(&b'E') {
        return None;
    }

    let args_tail = &nested[idx + 1..];
    let args = parse_itanium_args(args_tail).unwrap_or_else(|| vec!["...".to_string()]);
    let mut rendered = format!("{}({})", components.join("::"), args.join(", "));
    if is_const_method {
        rendered.push_str(" const");
    }
    Some(rendered)
}

fn parse_itanium_args(args: &str) -> Option<Vec<String>> {
    if args.is_empty() || args == "v" {
        return Some(Vec::new());
    }

    let mut remaining = args;
    let mut parsed = Vec::new();
    while !remaining.is_empty() {
        let (arg, rest) = parse_itanium_type(remaining)?;
        if arg != "void" {
            parsed.push(arg);
        }
        remaining = rest;
    }
    Some(parsed)
}

fn parse_itanium_type(input: &str) -> Option<(String, &str)> {
    let (head, rest) = input.split_at(1);
    match head {
        "v" => Some(("void".to_string(), rest)),
        "b" => Some(("bool".to_string(), rest)),
        "c" => Some(("char".to_string(), rest)),
        "a" => Some(("signed char".to_string(), rest)),
        "h" => Some(("unsigned char".to_string(), rest)),
        "s" => Some(("short".to_string(), rest)),
        "t" => Some(("unsigned short".to_string(), rest)),
        "i" => Some(("int".to_string(), rest)),
        "j" => Some(("unsigned int".to_string(), rest)),
        "l" => Some(("long".to_string(), rest)),
        "m" => Some(("unsigned long".to_string(), rest)),
        "x" => Some(("long long".to_string(), rest)),
        "y" => Some(("unsigned long long".to_string(), rest)),
        "f" => Some(("float".to_string(), rest)),
        "d" => Some(("double".to_string(), rest)),
        "P" => {
            let (inner, rest) = parse_itanium_type(rest)?;
            Some((format!("{inner}*"), rest))
        }
        "R" => {
            let (inner, rest) = parse_itanium_type(rest)?;
            Some((format!("{inner}&"), rest))
        }
        "K" => {
            let (inner, rest) = parse_itanium_type(rest)?;
            Some((format!("const {inner}"), rest))
        }
        _ => None,
    }
}

fn classify_strings(strings: &[BinaryString]) -> ClassifiedStrings {
    let ip_re = regex::Regex::new(r"\d+\.\d+\.\d+\.\d+").unwrap();

    let mut ip_addresses = Vec::new();
    let mut hostnames = Vec::new();
    let mut urls = Vec::new();
    let mut potential_secrets = Vec::new();
    let mut human_readable_messages = Vec::new();

    for s in strings {
        let lower = s.value.to_ascii_lowercase();
        let mut classified = false;

        if lower.starts_with("http://") || lower.starts_with("https://") {
            urls.push(StringEntry {
                value: s.value.clone(),
                address: s.address,
            });
            classified = true;
        }

        if ip_re.is_match(&s.value) {
            ip_addresses.push(StringEntry {
                value: s.value.clone(),
                address: s.address,
            });
            classified = true;
        }

        if lower.contains(".com") || lower.contains(".io") || lower.contains(".net") {
            hostnames.push(StringEntry {
                value: s.value.clone(),
                address: s.address,
            });
            classified = true;
        }

        if lower.contains("password")
            || lower.contains("key")
            || lower.contains("secret")
            || lower.contains("token")
        {
            potential_secrets.push(StringEntry {
                value: s.value.clone(),
                address: s.address,
            });
            classified = true;
        }

        if !classified && looks_human_readable_message(&s.value) {
            human_readable_messages.push(StringEntry {
                value: s.value.clone(),
                address: s.address,
            });
        }
    }

    ClassifiedStrings {
        ip_addresses,
        hostnames,
        urls,
        potential_secrets,
        human_readable_messages,
    }
}

fn looks_human_readable_message(value: &str) -> bool {
    if value.len() < 10 {
        return false;
    }

    let printable = value
        .chars()
        .filter(|c| c.is_ascii_graphic() || c.is_ascii_whitespace())
        .count();
    if printable * 10 < value.len() * 9 {
        return false;
    }

    let alpha_count = value.chars().filter(|c| c.is_ascii_alphabetic()).count();
    if alpha_count < 4 {
        return false;
    }

    let has_sentence_or_debug_structure = value.contains(' ')
        || value.contains('[')
        || value.contains(']')
        || value.contains('!')
        || value.contains('%')
        || value.contains(':')
        || value.contains('=')
        || value.contains('_');

    if !has_sentence_or_debug_structure {
        return false;
    }

    !value.chars().all(|c| c.is_ascii_alphanumeric())
}

fn detect_crypto_libraries(libs: &[String]) -> Vec<String> {
    libs.iter()
        .filter(|lib| {
            let lower = lib.to_ascii_lowercase();
            CRYPTO_LIBRARIES.iter().any(|c| lower.contains(c))
        })
        .cloned()
        .collect()
}

fn rank_functions_by_complexity(funcs: &[FunctionInfo], top_n: usize) -> Vec<FunctionReport> {
    let mut sorted: Vec<&FunctionInfo> = funcs.iter().collect();
    sorted.sort_by_key(|f| std::cmp::Reverse(f.cyclomatic_complexity));
    sorted
        .into_iter()
        .take(top_n)
        .map(|f| FunctionReport {
            name: demangle_cpp_symbol(&f.name),
            address: f.address,
            size: f.size,
            basic_blocks: f.basic_blocks,
            cyclomatic_complexity: f.cyclomatic_complexity,
        })
        .collect()
}

// ── Entry point ─────────────────────────────────────────────────────────────

pub fn run(
    file: &Path,
    arch: Option<&str>,
    base: Option<&str>,
    family: Option<&str>,
    json: bool,
    full: bool,
) -> DynResult<()> {
    if !file.is_file() {
        return Err(format!("file not found: {}", file.display()).into());
    }

    let palette = Palette::stdout();
    let panel_mode = !json && palette.enabled();
    let log = StageLog::begin(panel_mode, "r2-triage", file);
    let user_base = parse_base_address(base)?;
    let loader_hints = resolve_loader_hints(file, arch, user_base, family)
        .map_err(|err| -> Box<dyn Error> { err.into() })?;

    let (profile, exports, imports, strings, libs, functions) = if loader_hints.is_raw_blob {
        let hints = summarize_loader_hints(&loader_hints);
        log.stage(
            &format!("[raw] using loader hints: {hints}"),
            &format!("raw blob · {hints}"),
        );
        log.stage(
            "[1/4] synthetic profile from loader hints...",
            "profile (loader hints)",
        );
        log.stage(
            "[2/4] strings (rabin2 -zj, min_len=4)...",
            "strings (rabin2)",
        );
        let strings = r2::strings(file, 4)
            .map_err(|e| -> Box<dyn Error> { format!("strings: {e}").into() })?;
        log.stage(
            "[3/4] function analysis (r2 aaa + aflj with raw loader hints)...",
            "function analysis (r2)",
        );
        let functions = r2::function_list_with_options(
            file,
            Some(&r2::R2OpenOptions {
                arch: loader_hints.arch.clone(),
                bits: loader_hints.bits,
                base: loader_hints.base,
                cpu: loader_hints.cpu.clone(),
            }),
        )
        .map_err(|e| -> Box<dyn Error> { format!("function_list: {e}").into() })?;
        log.stage(
            "[4/4] skipping ELF-only imports/exports/library queries for raw blob...",
            "skipping ELF-only queries",
        );
        (
            synthetic_profile_from_loader(&loader_hints),
            Vec::new(),
            Vec::new(),
            strings,
            Vec::new(),
            functions,
        )
    } else {
        // 1. Binary profile
        log.stage("[1/6] binary profile (rabin2 -Ij)...", "profile (rabin2)");
        let profile = r2::binary_profile(file)
            .map_err(|e| -> Box<dyn Error> { format!("binary_profile: {e}").into() })?;

        // 2. Exports
        log.stage("[2/6] exports (rabin2 -Ej)...", "exports (rabin2)");
        let exports =
            r2::exports(file).map_err(|e| -> Box<dyn Error> { format!("exports: {e}").into() })?;

        // 3. Imports
        log.stage("[3/6] imports (rabin2 -ij)...", "imports (rabin2)");
        let imports =
            r2::imports(file).map_err(|e| -> Box<dyn Error> { format!("imports: {e}").into() })?;

        // 4. Strings
        log.stage(
            "[4/6] strings (rabin2 -zj, min_len=4)...",
            "strings (rabin2)",
        );
        let strings = r2::strings(file, 4)
            .map_err(|e| -> Box<dyn Error> { format!("strings: {e}").into() })?;

        // 5. Linked libraries
        log.stage(
            "[5/6] linked libraries (rabin2 -lj)...",
            "linked libraries (rabin2)",
        );
        let libs = r2::linked_libraries(file)
            .map_err(|e| -> Box<dyn Error> { format!("linked_libraries: {e}").into() })?;

        // 6. Function list (r2 session — slow)
        log.stage(
            "[6/6] function analysis (r2 aaa + aflj)...",
            "function analysis (r2)",
        );
        let functions = r2::function_list(file)
            .map_err(|e| -> Box<dyn Error> { format!("function_list: {e}").into() })?;
        (
            ProfileReport {
                arch: profile.arch,
                bits: profile.bits,
                compiler: profile.compiler,
                canary: profile.canary,
                nx: profile.nx,
                relro: profile.relro,
                stripped: profile.stripped,
                class: profile.class,
                family: None,
                raw_blob: false,
            },
            exports,
            imports,
            strings,
            libs,
            functions,
        )
    };

    log.finish();

    // Build report
    let dangerous = filter_dangerous_imports(&imports);
    let security_exports = filter_security_exports(&exports);
    let module_prefixes = group_by_module_prefix(&exports);
    let classified = classify_strings(&strings);
    let crypto = detect_crypto_libraries(&libs);
    let top_funcs = rank_functions_by_complexity(&functions, 20);
    let total_functions = functions.len();

    let report = TriageReport {
        profile,
        dangerous_imports: dangerous,
        security_exports,
        module_prefixes,
        classified_strings: classified,
        crypto_libraries: crypto,
        top_complex_functions: top_funcs,
        total_functions,
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if panel_mode {
        let binary_name = file
            .file_name()
            .map(|name| name.to_string_lossy().into_owned())
            .unwrap_or_else(|| file.display().to_string());
        let lines = panel_lines(&report, &palette, full);
        println!(
            "{}",
            palette.panel(&format!("fat r2-triage · {binary_name}"), &lines)
        );
    } else {
        render_text_report(&report);
    }

    Ok(())
}

// ── Text renderer ───────────────────────────────────────────────────────────

fn render_text_report(report: &TriageReport) {
    println!("=== Binary Audit Triage ===\n");

    // Profile
    println!("--- Profile ---");
    println!(
        "  Arch:     {} ({}bit)",
        report.profile.arch, report.profile.bits
    );
    println!("  Class:    {}", report.profile.class);
    println!(
        "  Raw blob: {}",
        if report.profile.raw_blob { "yes" } else { "no" }
    );
    if let Some(family) = report.profile.family.as_deref() {
        println!("  Family:   {family}");
    }
    println!(
        "  Compiler: {}",
        if report.profile.compiler.is_empty() {
            "unknown"
        } else {
            &report.profile.compiler
        }
    );
    println!(
        "  Canary:   {}",
        if report.profile.canary { "yes" } else { "NO" }
    );
    println!(
        "  NX:       {}",
        if report.profile.nx { "yes" } else { "NO" }
    );
    println!("  RELRO:    {}", report.profile.relro);
    println!(
        "  Stripped: {}",
        if report.profile.stripped { "yes" } else { "no" }
    );
    println!();

    // Dangerous imports
    println!(
        "--- Dangerous Imports ({}) ---",
        report.dangerous_imports.len()
    );
    if report.dangerous_imports.is_empty() {
        println!("  (none)");
    } else {
        for name in &report.dangerous_imports {
            println!("  !! {name}");
        }
    }
    println!();

    // Security-relevant exports
    println!(
        "--- Security-Relevant Exports ({}) ---",
        report.security_exports.len()
    );
    if report.security_exports.is_empty() {
        println!("  (none)");
    } else {
        for name in &report.security_exports {
            println!("  -> {name}");
        }
    }
    println!();

    // Module prefixes
    println!("--- Export Module Prefixes (top 15) ---");
    for mp in report.module_prefixes.iter().take(15) {
        println!("  {:>4}  {}", mp.count, mp.prefix);
    }
    println!();

    // Crypto libraries
    println!(
        "--- Crypto Libraries ({}) ---",
        report.crypto_libraries.len()
    );
    if report.crypto_libraries.is_empty() {
        println!("  (none detected)");
    } else {
        for lib in &report.crypto_libraries {
            println!("  * {lib}");
        }
    }
    println!();

    // Classified strings
    println!("--- Classified Strings ---");
    if !report.classified_strings.urls.is_empty() {
        println!("  URLs ({}):", report.classified_strings.urls.len());
        for s in &report.classified_strings.urls {
            println!("    0x{:08x}  {}", s.address, s.value);
        }
    }
    if !report.classified_strings.ip_addresses.is_empty() {
        println!(
            "  IP addresses ({}):",
            report.classified_strings.ip_addresses.len()
        );
        for s in &report.classified_strings.ip_addresses {
            println!("    0x{:08x}  {}", s.address, s.value);
        }
    }
    if !report.classified_strings.hostnames.is_empty() {
        println!(
            "  Hostnames ({}):",
            report.classified_strings.hostnames.len()
        );
        for s in &report.classified_strings.hostnames {
            println!("    0x{:08x}  {}", s.address, s.value);
        }
    }
    if !report.classified_strings.potential_secrets.is_empty() {
        println!(
            "  Potential secrets ({}):",
            report.classified_strings.potential_secrets.len()
        );
        for s in &report.classified_strings.potential_secrets {
            println!("    0x{:08x}  {}", s.address, s.value);
        }
    }
    if !report.classified_strings.human_readable_messages.is_empty() {
        println!(
            "  Human-readable messages ({}):",
            report.classified_strings.human_readable_messages.len()
        );
        for s in &report.classified_strings.human_readable_messages {
            println!("    0x{:08x}  {}", s.address, s.value);
        }
    }
    if report.classified_strings.urls.is_empty()
        && report.classified_strings.ip_addresses.is_empty()
        && report.classified_strings.hostnames.is_empty()
        && report.classified_strings.potential_secrets.is_empty()
        && report.classified_strings.human_readable_messages.is_empty()
    {
        println!("  (none)");
    }
    println!();

    // Top complex functions
    println!(
        "--- Audit Targets: Top {} by Cyclomatic Complexity ({} total functions) ---",
        report.top_complex_functions.len(),
        report.total_functions,
    );
    for f in &report.top_complex_functions {
        println!(
            "  cc={:<4} bbs={:<4} size={:<6} 0x{:08x}  {}",
            f.cyclomatic_complexity, f.basic_blocks, f.size, f.address, f.name,
        );
    }
    println!();
}

/// Pipeline stage announcements. Panel mode (colored TTY stdout) drives a
/// stderr spinner; plain piped output keeps the legacy `[n/m]` eprintlns
/// verbatim so redirected runs stay byte-identical.
enum StageLog {
    Spinner(PipelineProgress),
    Echo,
}

impl StageLog {
    fn begin(panel_mode: bool, label: &str, file: &Path) -> Self {
        if panel_mode {
            StageLog::Spinner(PipelineProgress::start(format!(
                "{label} · {}",
                file.display()
            )))
        } else {
            eprintln!("{label}: analyzing {}", file.display());
            StageLog::Echo
        }
    }

    /// Announce a stage: `echo` is the legacy `[n/m] ...` line, `spin` the
    /// short spinner label.
    fn stage(&self, echo: &str, spin: &str) {
        match self {
            StageLog::Spinner(sp) => sp.set_message(spin.to_string()),
            StageLog::Echo => eprintln!("  {echo}"),
        }
    }

    fn finish(&self) {
        match self {
            StageLog::Spinner(sp) => sp.finish_with("done"),
            StageLog::Echo => eprintln!("  done.\n"),
        }
    }
}

/// Append `items` to `lines`, capped at `PANEL_CAP` unless `full`; the
/// overflow becomes a dimmed `… N more` pointer at `--full`.
fn push_capped(lines: &mut Vec<String>, palette: &Palette, full: bool, items: Vec<String>) {
    if full || items.len() <= PANEL_CAP {
        lines.extend(items);
        return;
    }
    let overflow = items.len() - PANEL_CAP;
    lines.extend(items.into_iter().take(PANEL_CAP));
    lines.push(palette.muted(format!("… {overflow} more — use --full to expand")));
}

/// One classified-strings sub-list as dimmed sub-heading plus capped entries.
fn push_string_list(
    lines: &mut Vec<String>,
    palette: &Palette,
    full: bool,
    label: &str,
    entries: &[StringEntry],
) {
    if entries.is_empty() {
        return;
    }
    lines.push(palette.muted(format!("{label} ({}):", entries.len())));
    let items = entries
        .iter()
        .map(|s| {
            format!(
                "  {} {}",
                palette.muted(format!("0x{:08x}", s.address)),
                palette.muted(clipped_value(&s.value))
            )
        })
        .collect();
    push_capped(lines, palette, full, items);
}

/// Panel-mode display clip for classified string values: huge firmware
/// strings would otherwise wrap a single entry over many panel rows.
fn clipped_value(value: &str) -> String {
    const MAX: usize = 64;
    if value.chars().count() > MAX {
        let clipped: String = value.chars().take(MAX).collect();
        format!("{clipped}…")
    } else {
        value.to_string()
    }
}

/// Panel-mode display clip for audit-target symbol names so each ranked
/// function stays on one panel row.
fn clipped_name(name: &str) -> String {
    const MAX: usize = 44;
    if name.chars().count() > MAX {
        let clipped: String = name.chars().take(MAX).collect();
        format!("{clipped}…")
    } else {
        name.to_string()
    }
}

/// Panel-mode report body (colored TTY only; plain output stays verbatim).
fn panel_lines(report: &TriageReport, palette: &Palette, full: bool) -> Vec<String> {
    let mut lines = Vec::new();

    // Profile
    lines.push(palette.heading("Profile"));
    lines.push(palette.kv(
        "arch",
        format!("{} ({}bit)", report.profile.arch, report.profile.bits),
    ));
    lines.push(palette.kv("class", &report.profile.class));
    lines.push(palette.kv(
        "raw blob",
        if report.profile.raw_blob { "yes" } else { "no" },
    ));
    if let Some(family) = report.profile.family.as_deref() {
        lines.push(palette.kv("family", family));
    }
    lines.push(palette.kv(
        "compiler",
        if report.profile.compiler.is_empty() {
            "unknown"
        } else {
            &report.profile.compiler
        },
    ));
    lines.push(palette.kv(
        "canary",
        if report.profile.canary {
            palette.good("yes")
        } else {
            palette.bad("NO")
        },
    ));
    lines.push(palette.kv(
        "nx",
        if report.profile.nx {
            palette.good("yes")
        } else {
            palette.bad("NO")
        },
    ));
    lines.push(palette.kv("relro", &report.profile.relro));
    lines.push(palette.kv(
        "stripped",
        if report.profile.stripped { "yes" } else { "no" },
    ));
    lines.push(String::new());

    // Dangerous imports
    lines.push(palette.heading(format!(
        "Dangerous imports ({})",
        report.dangerous_imports.len()
    )));
    if report.dangerous_imports.is_empty() {
        lines.push(palette.muted("none"));
    } else {
        let items = report
            .dangerous_imports
            .iter()
            .map(|name| format!("  {} {}", palette.dot_bad(), palette.code(name)))
            .collect();
        push_capped(&mut lines, palette, full, items);
    }
    lines.push(String::new());

    // Security-relevant exports
    lines.push(palette.heading(format!(
        "Security-relevant exports ({})",
        report.security_exports.len()
    )));
    if report.security_exports.is_empty() {
        lines.push(palette.muted("none"));
    } else {
        let items = report
            .security_exports
            .iter()
            .map(|name| format!("  {} {}", palette.dot_ok(), palette.code(name)))
            .collect();
        push_capped(&mut lines, palette, full, items);
    }
    lines.push(String::new());

    // Export module prefixes
    lines.push(palette.heading("Export module prefixes"));
    if report.module_prefixes.is_empty() {
        lines.push(palette.muted("none"));
    } else {
        let items = report
            .module_prefixes
            .iter()
            .map(|mp| {
                format!(
                    "  {} {}",
                    palette.muted(format!("{:>4}", mp.count)),
                    mp.prefix
                )
            })
            .collect();
        push_capped(&mut lines, palette, full, items);
    }
    lines.push(String::new());

    // Crypto libraries
    lines.push(palette.heading(format!(
        "Crypto libraries ({})",
        report.crypto_libraries.len()
    )));
    if report.crypto_libraries.is_empty() {
        lines.push(palette.muted("none detected"));
    } else {
        let items = report
            .crypto_libraries
            .iter()
            .map(|lib| format!("  {} {}", palette.dot_ok(), palette.good(lib)))
            .collect();
        push_capped(&mut lines, palette, full, items);
    }
    lines.push(String::new());

    // Classified strings
    lines.push(palette.heading("Classified strings"));
    let classified = &report.classified_strings;
    if classified.urls.is_empty()
        && classified.ip_addresses.is_empty()
        && classified.hostnames.is_empty()
        && classified.potential_secrets.is_empty()
        && classified.human_readable_messages.is_empty()
    {
        lines.push(palette.muted("none"));
    } else {
        push_string_list(&mut lines, palette, full, "URLs", &classified.urls);
        push_string_list(
            &mut lines,
            palette,
            full,
            "IP addresses",
            &classified.ip_addresses,
        );
        push_string_list(
            &mut lines,
            palette,
            full,
            "Hostnames",
            &classified.hostnames,
        );
        push_string_list(
            &mut lines,
            palette,
            full,
            "Potential secrets",
            &classified.potential_secrets,
        );
        push_string_list(
            &mut lines,
            palette,
            full,
            "Human-readable messages",
            &classified.human_readable_messages,
        );
    }
    lines.push(String::new());

    // Audit targets (the payload)
    lines.push(palette.heading(format!(
        "Audit targets · top {} by complexity ({} total functions)",
        report.top_complex_functions.len(),
        report.total_functions,
    )));
    if report.top_complex_functions.is_empty() {
        lines.push(palette.muted("none"));
    } else {
        let items = report
            .top_complex_functions
            .iter()
            .map(|f| {
                format!(
                    "  {} cc={} bbs={} size={} {} {}",
                    palette.dot_ok(),
                    palette.muted(f.cyclomatic_complexity.to_string()),
                    palette.muted(f.basic_blocks.to_string()),
                    palette.muted(f.size.to_string()),
                    palette.muted(format!("0x{:08x}", f.address)),
                    palette.code(clipped_name(&f.name)),
                )
            })
            .collect();
        push_capped(&mut lines, palette, full, items);
    }

    lines
}

fn synthetic_profile_from_loader(loader_hints: &LoaderHints) -> ProfileReport {
    ProfileReport {
        arch: loader_hints
            .arch
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
        bits: loader_hints.bits.unwrap_or(0),
        compiler: String::new(),
        canary: false,
        nx: false,
        relro: "unknown".to_string(),
        stripped: false,
        class: "raw-firmware".to_string(),
        family: loader_hints.family.clone(),
        raw_blob: true,
    }
}

fn parse_base_address(base: Option<&str>) -> DynResult<Option<u32>> {
    let Some(base) = base else {
        return Ok(None);
    };
    if let Some(hex) = base.strip_prefix("0x").or_else(|| base.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16)
            .map(Some)
            .map_err(|_| invalid_base_error(base))
    } else {
        base.parse::<u32>()
            .map(Some)
            .map_err(|_| invalid_base_error(base))
    }
}

fn invalid_base_error(base: &str) -> Box<dyn Error> {
    format!("invalid --base value '{base}' (expected decimal or 0x-prefixed hex)").into()
}

fn summarize_loader_hints(loader_hints: &LoaderHints) -> String {
    let mut parts = Vec::new();
    if let Some(arch) = loader_hints.arch.as_deref() {
        parts.push(format!("arch={arch}"));
    }
    if let Some(bits) = loader_hints.bits {
        parts.push(format!("bits={bits}"));
    }
    if let Some(base) = loader_hints.base {
        parts.push(format!("base=0x{base:08x}"));
    }
    if let Some(cpu) = loader_hints.cpu.as_deref() {
        parts.push(format!("cpu={cpu}"));
    }
    if let Some(family) = loader_hints.family.as_deref() {
        parts.push(format!("family={family}"));
    }
    if parts.is_empty() {
        "none".to_string()
    } else {
        parts.join(", ")
    }
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── Dangerous import filtering ──────────────────────────────────────

    #[test]
    fn test_filter_dangerous_imports_finds_exact_matches() {
        let imports = vec![
            Import {
                name: "strcpy".to_string(),
            },
            Import {
                name: "malloc".to_string(),
            },
            Import {
                name: "system".to_string(),
            },
            Import {
                name: "free".to_string(),
            },
            Import {
                name: "sprintf".to_string(),
            },
            Import {
                name: "tgetstr".to_string(),
            }, // should NOT match "gets"
        ];
        let result = filter_dangerous_imports(&imports);
        assert_eq!(result, vec!["strcpy", "system", "sprintf"]);
    }

    #[test]
    fn test_filter_dangerous_imports_empty_when_no_match() {
        let imports = vec![
            Import {
                name: "malloc".to_string(),
            },
            Import {
                name: "free".to_string(),
            },
        ];
        let result = filter_dangerous_imports(&imports);
        assert!(result.is_empty());
    }

    // ── Security export filtering ───────────────────────────────────────

    #[test]
    fn test_filter_security_exports() {
        let exports = vec![
            Export {
                name: "auth_check".to_string(),
                size: 128,
            },
            Export {
                name: "httpd_main".to_string(),
                size: 512,
            },
            Export {
                name: "encrypt_payload".to_string(),
                size: 256,
            },
            Export {
                name: "parse_json".to_string(),
                size: 64,
            },
            Export {
                name: "session_start".to_string(),
                size: 96,
            },
        ];
        let result = filter_security_exports(&exports);
        assert_eq!(
            result,
            vec!["auth_check", "encrypt_payload", "session_start"]
        );
    }

    #[test]
    fn test_filter_security_exports_case_insensitive() {
        let exports = vec![
            Export {
                name: "AES_encrypt".to_string(),
                size: 128,
            },
            Export {
                name: "RSA_sign".to_string(),
                size: 256,
            },
        ];
        let result = filter_security_exports(&exports);
        assert_eq!(result, vec!["AES_encrypt", "RSA_sign"]);
    }

    #[test]
    fn test_filter_security_exports_matches_demangled_cpp_names() {
        let exports = vec![
            Export {
                name: "_ZN7unitree7package7CodeKey8GenerateEPhj".to_string(),
                size: 128,
            },
            Export {
                name: "_ZN6google8protobuf2io9Tokenizer8NextCharEv".to_string(),
                size: 64,
            },
        ];
        let result = filter_security_exports(&exports);
        assert_eq!(
            result,
            vec![
                "unitree::package::CodeKey::Generate(unsigned char*, unsigned int)",
                "google::protobuf::io::Tokenizer::NextChar()",
            ]
        );
    }

    #[test]
    fn test_demangle_cpp_export_name_with_void_method() {
        assert_eq!(
            demangle_cpp_symbol("_ZN6google8protobuf2io9Tokenizer8NextCharEv"),
            "google::protobuf::io::Tokenizer::NextChar()"
        );
    }

    #[test]
    fn test_demangle_cpp_export_name_with_complex_arguments() {
        let demangled = demangle_cpp_symbol(
            "_ZN6google8protobuf2io9Tokenizer16NextWithCommentsEPNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEEPS6_",
        );
        assert!(demangled.starts_with("google::protobuf::io::Tokenizer::NextWithComments("));
        assert!(!demangled.starts_with("_ZN"));
    }

    #[test]
    fn test_demangle_cpp_export_name_with_abi_tag() {
        assert_eq!(
            demangle_cpp_symbol("_ZNK7unitree3ota7OTATask8GetTokenB5cxx11Ev"),
            "unitree::ota::OTATask::GetToken() const"
        );
    }

    // ── Module prefix grouping ──────────────────────────────────────────

    #[test]
    fn test_group_by_module_prefix() {
        let exports = vec![
            Export {
                name: "httpd_main".to_string(),
                size: 0,
            },
            Export {
                name: "httpd_handler".to_string(),
                size: 0,
            },
            Export {
                name: "httpd_init".to_string(),
                size: 0,
            },
            Export {
                name: "auth_check".to_string(),
                size: 0,
            },
            Export {
                name: "auth_login".to_string(),
                size: 0,
            },
            Export {
                name: "main".to_string(),
                size: 0,
            },
        ];
        let result = group_by_module_prefix(&exports);
        // Sorted descending by count: httpd=3, auth=2, main=1
        assert_eq!(result[0].prefix, "httpd");
        assert_eq!(result[0].count, 3);
        assert_eq!(result[1].prefix, "auth");
        assert_eq!(result[1].count, 2);
        assert_eq!(result[2].prefix, "main");
        assert_eq!(result[2].count, 1);
    }

    #[test]
    fn test_group_by_module_prefix_uses_demangled_namespace() {
        let exports = vec![
            Export {
                name: "_ZN7unitree7package7CodeKey8GenerateEPhj".to_string(),
                size: 0,
            },
            Export {
                name: "_ZN7unitree7package7CodeKey5HByteEj".to_string(),
                size: 0,
            },
            Export {
                name: "_ZN6google8protobuf2io9Tokenizer8NextCharEv".to_string(),
                size: 0,
            },
        ];
        let result = group_by_module_prefix(&exports);
        assert_eq!(result[0].prefix, "unitree");
        assert_eq!(result[0].count, 2);
        assert_eq!(result[1].prefix, "google");
        assert_eq!(result[1].count, 1);
    }

    // ── String classification ───────────────────────────────────────────

    #[test]
    fn test_classify_strings_urls() {
        let strings = vec![
            BinaryString {
                value: "http://192.168.1.1/login".to_string(),
                address: 0x1000,
                length: 23,
            },
            BinaryString {
                value: "https://api.example.com/v1".to_string(),
                address: 0x2000,
                length: 25,
            },
            BinaryString {
                value: "not a url".to_string(),
                address: 0x3000,
                length: 9,
            },
        ];
        let result = classify_strings(&strings);
        assert_eq!(result.urls.len(), 2);
        assert_eq!(result.urls[0].value, "http://192.168.1.1/login");
        assert_eq!(result.urls[1].value, "https://api.example.com/v1");
    }

    #[test]
    fn test_classify_strings_ip_addresses() {
        let strings = vec![
            BinaryString {
                value: "192.168.1.1".to_string(),
                address: 0x1000,
                length: 11,
            },
            BinaryString {
                value: "connect to 10.0.0.1 port 80".to_string(),
                address: 0x2000,
                length: 27,
            },
            BinaryString {
                value: "no ip here".to_string(),
                address: 0x3000,
                length: 10,
            },
        ];
        let result = classify_strings(&strings);
        assert_eq!(result.ip_addresses.len(), 2);
    }

    #[test]
    fn test_classify_strings_hostnames() {
        let strings = vec![
            BinaryString {
                value: "api.example.com".to_string(),
                address: 0x1000,
                length: 15,
            },
            BinaryString {
                value: "data.service.io".to_string(),
                address: 0x2000,
                length: 15,
            },
            BinaryString {
                value: "updates.vendor.net".to_string(),
                address: 0x3000,
                length: 18,
            },
            BinaryString {
                value: "not a hostname".to_string(),
                address: 0x4000,
                length: 14,
            },
        ];
        let result = classify_strings(&strings);
        assert_eq!(result.hostnames.len(), 3);
    }

    #[test]
    fn test_classify_strings_potential_secrets() {
        let strings = vec![
            BinaryString {
                value: "password=admin".to_string(),
                address: 0x1000,
                length: 14,
            },
            BinaryString {
                value: "api_key=abc123".to_string(),
                address: 0x2000,
                length: 14,
            },
            BinaryString {
                value: "secret_token".to_string(),
                address: 0x3000,
                length: 12,
            },
            BinaryString {
                value: "hello world".to_string(),
                address: 0x4000,
                length: 11,
            },
        ];
        let result = classify_strings(&strings);
        // "password=admin" matches password
        // "api_key=abc123" matches key
        // "secret_token" matches both secret and token
        assert_eq!(result.potential_secrets.len(), 3);
    }

    #[test]
    fn test_classify_strings_human_readable_messages() {
        let strings = vec![
            BinaryString {
                value: "Charlie is the designer of P2P!!".to_string(),
                address: 0x1000,
                length: 32,
            },
            BinaryString {
                value: "[TCP][%s][%d]verify_value[%u]".to_string(),
                address: 0x2000,
                length: 31,
            },
            BinaryString {
                value: "api.example.com".to_string(),
                address: 0x3000,
                length: 15,
            },
            BinaryString {
                value: "ABCD".to_string(),
                address: 0x4000,
                length: 4,
            },
        ];
        let result = classify_strings(&strings);
        assert_eq!(result.human_readable_messages.len(), 2);
        assert_eq!(
            result.human_readable_messages[0].value,
            "Charlie is the designer of P2P!!"
        );
        assert_eq!(
            result.human_readable_messages[1].value,
            "[TCP][%s][%d]verify_value[%u]"
        );
    }

    // ── Crypto library detection ────────────────────────────────────────

    #[test]
    fn test_detect_crypto_libraries() {
        let libs = vec![
            "libc.so.6".to_string(),
            "libssl.so.1.1".to_string(),
            "libcrypto.so.1.1".to_string(),
            "libpthread.so.0".to_string(),
        ];
        let result = detect_crypto_libraries(&libs);
        assert_eq!(result, vec!["libssl.so.1.1", "libcrypto.so.1.1"]);
    }

    #[test]
    fn test_detect_crypto_libraries_none() {
        let libs = vec!["libc.so.6".to_string(), "libm.so.6".to_string()];
        let result = detect_crypto_libraries(&libs);
        assert!(result.is_empty());
    }

    // ── Function complexity ranking ─────────────────────────────────────

    #[test]
    fn test_rank_functions_by_complexity() {
        let funcs = vec![
            FunctionInfo {
                name: "simple".to_string(),
                address: 0x1000,
                size: 32,
                basic_blocks: 1,
                cyclomatic_complexity: 1,
            },
            FunctionInfo {
                name: "complex".to_string(),
                address: 0x2000,
                size: 1024,
                basic_blocks: 50,
                cyclomatic_complexity: 42,
            },
            FunctionInfo {
                name: "medium".to_string(),
                address: 0x3000,
                size: 256,
                basic_blocks: 10,
                cyclomatic_complexity: 8,
            },
        ];
        let result = rank_functions_by_complexity(&funcs, 2);
        assert_eq!(result.len(), 2);
        assert_eq!(result[0].name, "complex");
        assert_eq!(result[0].cyclomatic_complexity, 42);
        assert_eq!(result[1].name, "medium");
        assert_eq!(result[1].cyclomatic_complexity, 8);
    }

    #[test]
    fn test_rank_functions_empty() {
        let funcs: Vec<FunctionInfo> = vec![];
        let result = rank_functions_by_complexity(&funcs, 10);
        assert!(result.is_empty());
    }
}
