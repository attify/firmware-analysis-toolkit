use crate::schema_versions;
use crate::style::Palette;
use regex::{Regex, RegexBuilder};
use serde::Serialize;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fs;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};
use std::process::Command;
use walkdir::WalkDir;

type DynResult<T> = Result<T, Box<dyn Error>>;

const DEFAULT_BINARY_DIRS: &[&str] = &["bin", "sbin", "usr/bin", "usr/sbin", "usr/lib", "lib"];
const DISCOVERY_SKIP_DIRS: &[&str] = &[".git", ".worktrees", "target", "node_modules"];
const DISCOVERY_MAX_DEPTH: usize = 4;
const ROOTFS_MARKER_DIRS: &[&str] = &["bin", "sbin", "lib", "usr", "etc"];
/// Directory names that suggest an extracted root filesystem. These are
/// extractor conventions, not device names: a vendor-specific directory name
/// must not decide what FAT scans, so a tree named for a particular product is
/// reached with an explicit `--path` instead. `ROOTFS_MARKER_DIRS` remains the
/// evidence-based test and still finds such a tree on its contents.
const ROOTFS_NAME_HINTS: &[&str] = &["squashfs-root", "rootfs"];
const ROOTFS_ELF_DIRS: &[&str] = &["bin", "sbin", "usr/bin", "usr/sbin", "lib", "usr/lib"];
const PATH_LITERAL_SCORE: usize = 10;
const ACCESSOR_SCORE: usize = 1;
const SUBSTRING_SCORE: usize = 1;
const TEXT_DETECTION_SAMPLE_BYTES: usize = 8192;
const TEXT_DETECTION_MIN_RATIO: f64 = 0.85;
const TEXT_SNIPPET_LIMIT: usize = 160;
const SEARCH_SECTION_DIVIDER: &str = "────────────────────────────────────────────────────────────";
const BUILTIN_PROFILES: &[(&str, &str)] = &[
    (
        "credentials",
        r"password|passwd|secret|token|apikey|api_key|credential|auth",
    ),
    (
        "urls",
        r"https?://|mqtt://|wss?://|[a-zA-Z0-9.-]+\.(com|net|org|io)",
    ),
    (
        "crypto",
        r"aes|rsa|sha256|sha1|md5|hmac|encrypt|decrypt|private key|certificate",
    ),
    (
        "sinks",
        r"system|popen|execve|/bin/sh|sh -c|wget|curl|tftp|nc",
    ),
    (
        "debug",
        r"debug|trace|verbose|assert|panic|backtrace|telnet|uart|console",
    ),
];

pub struct SearchRequest<'a> {
    pub rootfs: &'a Path,
    pub include: Option<&'a str>,
    pub excludes: &'a [String],
    pub profiles: &'a [String],
    pub path: Option<&'a Path>,
    pub max: usize,
    pub all_files: bool,
    pub min_len: usize,
    pub case_insensitive: bool,
    pub context: usize,
    pub unique: bool,
    pub discover_rootfs: bool,
    pub show_empty: bool,
    pub min_strength: &'a str,
    pub context_filter: &'a str,
    pub verbose: bool,
    pub summary: bool,
    pub format: &'a str,
    pub color: Option<&'a str>,
    pub progress: &'a str,
    pub json: bool,
}

#[derive(Debug, Serialize)]
pub struct SearchReport {
    pub schema_version: &'static str,
    pub rootfs_path: String,
    pub rootfs_candidates: Vec<String>,
    pub discover_rootfs: bool,
    pub case_insensitive: bool,
    pub profiles: Vec<String>,
    pub scope: String,
    pub include: String,
    pub exclude: Vec<String>,
    pub path_filter: Option<String>,
    pub min_len: usize,
    pub max_per_file: usize,
    pub min_strength: String,
    pub scoring: SearchScoring,
    pub files_scanned: usize,
    pub files_skipped: usize,
    pub files_with_matches: usize,
    pub scanned_files_without_matches: Vec<String>,
    pub ranked_files: Vec<RankedFileMatch>,
    pub shared_strings: Vec<SharedStringMatch>,
    pub matches: Vec<FileMatches>,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct SearchScoring {
    pub literal_path: usize,
    pub accessor: usize,
    pub substring: usize,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct FileMatches {
    pub path: String,
    pub file_kind: String,
    pub match_count: usize,
    pub unique_match_count: usize,
    pub score: usize,
    pub strength: String,
    pub path_literal_count: usize,
    pub accessor_count: usize,
    pub size_bytes: u64,
    pub strings: Vec<StringMatch>,
    pub truncated: bool,
    #[serde(skip)]
    matched_values: HashSet<String>,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct RankedFileMatch {
    pub path: String,
    pub match_count: usize,
    pub unique_match_count: usize,
    pub score: usize,
    pub strength: String,
    pub path_literal_count: usize,
    pub accessor_count: usize,
    pub size_bytes: u64,
    pub truncated: bool,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct SharedStringMatch {
    pub value: String,
    pub file_count: usize,
    pub files: Vec<String>,
}

#[derive(Debug, Clone)]
struct ExtractedString {
    index: usize,
    offset: usize,
    line_number: usize,
    value: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ExtractionMode {
    PrintableStrings,
    TextLines,
}

#[derive(Debug)]
struct FileEvaluation {
    strings: Vec<StringMatch>,
    match_count: usize,
    unique_match_count: usize,
    matched_values: HashSet<String>,
    truncated: bool,
    score: usize,
    strength: String,
    path_literal_count: usize,
    accessor_count: usize,
}

struct SearchProgress {
    mode: ProgressMode,
    total_files: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProgressMode {
    Never,
    Human,
}

impl SearchProgress {
    fn new(raw_mode: &str) -> Self {
        let mode = match raw_mode {
            "human" => ProgressMode::Human,
            _ => ProgressMode::Never,
        };

        Self {
            mode,
            total_files: 0,
        }
    }

    fn candidates(&mut self, total_files: usize) {
        self.total_files = total_files;
        if self.mode == ProgressMode::Human {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(stderr, "Search progress");
            let _ = writeln!(stderr, "scan candidates: {total_files} files");
        }
    }

    fn scanned(
        &self,
        processed_files: usize,
        files_scanned: usize,
        files_with_matches: usize,
        files_skipped: usize,
    ) {
        if self.mode == ProgressMode::Human {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(
                stderr,
                "scanned {}/{} files, eligible {}, matched {}, skipped {}",
                processed_files, self.total_files, files_scanned, files_with_matches, files_skipped
            );
        }
    }

    fn complete(
        &self,
        processed_files: usize,
        files_scanned: usize,
        files_with_matches: usize,
        files_skipped: usize,
    ) {
        if self.mode == ProgressMode::Human {
            let mut stderr = io::stderr().lock();
            let _ = writeln!(
                stderr,
                "scan complete: scanned {}/{} files, eligible {}, matched {}, skipped {}",
                processed_files, self.total_files, files_scanned, files_with_matches, files_skipped
            );
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum MatchKind {
    LiteralPath,
    Accessor,
    Substring,
}

impl MatchKind {
    fn as_str(self) -> &'static str {
        match self {
            MatchKind::LiteralPath => "literal-path",
            MatchKind::Accessor => "accessor",
            MatchKind::Substring => "substring",
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct MatchClassification {
    kind: MatchKind,
    strength: &'static str,
    score: usize,
}

fn classify_match(value: &str) -> MatchClassification {
    if looks_like_path_literal(value) {
        MatchClassification {
            kind: MatchKind::LiteralPath,
            strength: "STRONG",
            score: PATH_LITERAL_SCORE,
        }
    } else if looks_like_accessor(value) {
        MatchClassification {
            kind: MatchKind::Accessor,
            strength: "MEDIUM",
            score: ACCESSOR_SCORE,
        }
    } else {
        MatchClassification {
            kind: MatchKind::Substring,
            strength: "WEAK",
            score: SUBSTRING_SCORE,
        }
    }
}

fn looks_like_path_literal(value: &str) -> bool {
    value.contains('/') || value.contains('\\')
}

fn looks_like_accessor(value: &str) -> bool {
    value.contains("_get_")
        || value.starts_with("get_")
        || value.ends_with("_get")
        || value.contains("_set_")
        || value.starts_with("set_")
}

fn file_strength(score: usize, path_literal_count: usize, accessor_count: usize) -> &'static str {
    if path_literal_count > 0 || score >= 10 {
        "STRONG"
    } else if accessor_count >= 2 || score >= 2 {
        "MEDIUM"
    } else {
        "WEAK"
    }
}

fn strength_rank(strength: &str) -> usize {
    match strength.to_ascii_lowercase().as_str() {
        "strong" => 2,
        "medium" => 1,
        _ => 0,
    }
}

fn strength_meets(strength: &str, min_strength: &str) -> bool {
    strength_rank(strength) >= strength_rank(min_strength)
}

fn is_filtered_context(value: &str, context_filter: &str) -> bool {
    if context_filter != "boilerplate" {
        return false;
    }
    let lower = value.to_ascii_lowercase();
    if lower.ends_with(".so")
        || lower.contains(".so.")
        || lower == "libc.so"
        || lower.starts_with("libgcc_s.so")
        || lower.starts_with("libstdc++.so")
    {
        return true;
    }
    matches!(
        lower.as_str(),
        "libgcc_s.so.1"
            | "libstdc++.so.6"
            | "libcjson.so"
            | "libc.so.6"
            | "ld-linux.so.3"
            | "ld-uclibc.so.0"
    )
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct StringMatch {
    pub value: String,
    pub offset: usize,
    pub line_number: usize,
    pub kind: String,
    pub strength: String,
    pub score: usize,
    pub context_before: Vec<String>,
    pub context_after: Vec<String>,
}

pub fn run(request: SearchRequest<'_>) -> DynResult<()> {
    let report = search(&request)?;
    if request.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        let palette = Palette::stdout_with_color(request.color);
        match request.format {
            "anchor" => render_anchor_report(&report),
            _ if request.summary => render_summary_report(&report, &palette),
            _ => render_report(&report, &palette, &request),
        }
    }
    Ok(())
}

pub fn search(request: &SearchRequest<'_>) -> DynResult<SearchReport> {
    if !request.rootfs.is_dir() {
        return Err(format!(
            "rootfs path is not a directory: {}",
            request.rootfs.display()
        )
        .into());
    }
    if request.max == 0 {
        return Err("max must be greater than 0".into());
    }
    if request.min_len == 0 {
        return Err("min_len must be greater than 0".into());
    }
    if request.include.is_none() && request.profiles.is_empty() {
        return Err("provide --include or --profile".into());
    }

    let canonical_rootfs = request.rootfs.canonicalize().map_err(|err| {
        format!(
            "failed to canonicalize rootfs {}: {err}",
            request.rootfs.display()
        )
    })?;

    let include_regex = match request.include {
        Some(include) => Some(compile_regex(include, request.case_insensitive, "include")?),
        None => None,
    };
    let profile_patterns = compile_profile_regexes(request.profiles, request.case_insensitive)?;
    let profile_regexes = profile_patterns
        .iter()
        .map(|(_, regex)| regex.clone())
        .collect::<Vec<_>>();
    let mut exclude_regexes = Vec::with_capacity(request.excludes.len());
    for raw in request.excludes {
        let regex = compile_regex(raw, request.case_insensitive, "exclude")
            .map_err(|err| format!("invalid exclude regex '{raw}': {err}"))?;
        exclude_regexes.push(regex);
    }

    let (search_roots, mut files_skipped, path_filter, rootfs_candidates) = collect_search_roots(
        &canonical_rootfs,
        request.path,
        request.all_files,
        request.discover_rootfs,
    )?;
    let explicit_file = request
        .path
        .map(|path| canonical_rootfs.join(path).is_file())
        .unwrap_or(false);
    let mut progress = SearchProgress::new(request.progress);
    progress.candidates(search_roots.len());
    let mut files_scanned = 0usize;
    let mut matches = Vec::new();
    let mut scanned_files_without_matches = Vec::new();

    let mut files_processed = 0usize;
    for candidate in search_roots {
        files_processed += 1;
        let bytes = match fs::read(&candidate) {
            Ok(bytes) => bytes,
            Err(_) => {
                files_skipped += 1;
                progress.scanned(files_processed, files_scanned, matches.len(), files_skipped);
                continue;
            }
        };

        let is_elf = is_elf_bytes(&bytes);
        if !request.all_files && !is_elf {
            progress.scanned(files_processed, files_scanned, matches.len(), files_skipped);
            continue;
        }
        let is_text = !is_elf && is_probably_text_content(&bytes);
        let is_raw_mcu =
            !is_elf && !is_text && fat_analyze::mcu::detect_cortex_m_ivt(&bytes).is_some();
        if !is_elf && !is_text && !explicit_file && !is_raw_mcu {
            files_skipped += 1;
            progress.scanned(files_processed, files_scanned, matches.len(), files_skipped);
            continue;
        }

        let extraction_mode = if is_elf || !is_text {
            ExtractionMode::PrintableStrings
        } else {
            ExtractionMode::TextLines
        };
        let extracted = extract_strings(&bytes, request.min_len, extraction_mode);
        let evaluation = evaluate_file_matches(
            &extracted,
            include_regex.as_ref(),
            &profile_regexes,
            &exclude_regexes,
            request.max,
            request.context,
            request.unique,
            request.min_strength,
            request.context_filter,
            extraction_mode,
        );
        files_scanned += 1;
        let relative_path = rootfs_relative(&canonical_rootfs, &candidate);

        if !evaluation.strings.is_empty() {
            matches.push(FileMatches {
                path: relative_path,
                file_kind: if is_elf {
                    "elf"
                } else if is_text {
                    "text"
                } else {
                    "raw"
                }
                .to_string(),
                match_count: evaluation.match_count,
                unique_match_count: evaluation.unique_match_count,
                score: evaluation.score,
                strength: evaluation.strength,
                path_literal_count: evaluation.path_literal_count,
                accessor_count: evaluation.accessor_count,
                size_bytes: bytes.len() as u64,
                strings: evaluation.strings,
                truncated: evaluation.truncated,
                matched_values: evaluation.matched_values,
            });
        } else {
            scanned_files_without_matches.push(relative_path);
        }
        progress.scanned(files_processed, files_scanned, matches.len(), files_skipped);
    }

    matches.sort_by(|left, right| left.path.cmp(&right.path));
    let files_with_matches = matches.len();
    let ranked_files = build_ranked_files(&matches);
    let shared_strings = build_shared_strings(&matches);
    progress.complete(
        files_processed,
        files_scanned,
        files_with_matches,
        files_skipped,
    );

    Ok(SearchReport {
        schema_version: schema_versions::SEARCH_REPORT_V2,
        rootfs_path: request.rootfs.display().to_string(),
        rootfs_candidates,
        discover_rootfs: request.discover_rootfs,
        case_insensitive: request.case_insensitive,
        profiles: request.profiles.to_vec(),
        scope: if request.all_files {
            "all-files".to_string()
        } else {
            "elf-binaries".to_string()
        },
        include: effective_include_display(request.include, &profile_patterns),
        exclude: request.excludes.to_vec(),
        path_filter,
        min_len: request.min_len,
        max_per_file: request.max,
        min_strength: request.min_strength.to_string(),
        scoring: SearchScoring {
            literal_path: PATH_LITERAL_SCORE,
            accessor: ACCESSOR_SCORE,
            substring: SUBSTRING_SCORE,
        },
        files_scanned,
        files_skipped,
        files_with_matches,
        scanned_files_without_matches,
        ranked_files,
        shared_strings,
        matches,
    })
}

fn compile_regex(pattern: &str, case_insensitive: bool, kind: &str) -> DynResult<Regex> {
    RegexBuilder::new(pattern)
        .case_insensitive(case_insensitive)
        .build()
        .map_err(|err| -> Box<dyn Error> { format!("invalid {kind} regex: {err}").into() })
}

fn compile_profile_regexes(
    profiles: &[String],
    case_insensitive: bool,
) -> DynResult<Vec<(String, Regex)>> {
    let mut compiled = Vec::with_capacity(profiles.len());

    for profile in profiles {
        let Some(pattern) = builtin_profile_pattern(profile) else {
            return Err(format!(
                "unknown search profile '{profile}'; valid profiles: {}",
                valid_profile_names().join(", ")
            )
            .into());
        };

        let regex = RegexBuilder::new(pattern)
            .case_insensitive(case_insensitive)
            .build()
            .map_err(|err| -> Box<dyn Error> {
                format!("invalid profile regex for '{profile}': {err}").into()
            })?;
        compiled.push((pattern.to_string(), regex));
    }

    Ok(compiled)
}

fn builtin_profile_pattern(profile: &str) -> Option<&'static str> {
    BUILTIN_PROFILES
        .iter()
        .find(|(name, _)| *name == profile)
        .map(|(_, pattern)| *pattern)
}

fn valid_profile_names() -> Vec<&'static str> {
    BUILTIN_PROFILES.iter().map(|(name, _)| *name).collect()
}

fn effective_include_display(include: Option<&str>, profiles: &[(String, Regex)]) -> String {
    let mut parts = Vec::new();
    if let Some(include) = include {
        parts.push(include.to_string());
    }
    parts.extend(profiles.iter().map(|(pattern, _)| pattern.clone()));
    parts.join("|")
}

fn collect_search_roots(
    canonical_rootfs: &Path,
    path: Option<&Path>,
    all_files: bool,
    discover_rootfs: bool,
) -> DynResult<(Vec<PathBuf>, usize, Option<String>, Vec<String>)> {
    let mut files = Vec::new();
    let mut files_skipped = 0usize;
    let mut path_filter = None;
    let mut rootfs_candidates = Vec::new();

    if let Some(path) = path {
        validate_relative_path(path)?;
        let full = canonical_rootfs.join(path);
        if !full.exists() {
            return Err(format!("search path does not exist: {}", full.display()).into());
        }
        let canonical = full.canonicalize().map_err(|err| {
            format!(
                "failed to canonicalize search path {}: {err}",
                full.display()
            )
        })?;
        if !canonical.starts_with(canonical_rootfs) {
            return Err(format!(
                "search path escapes rootfs: {} is outside {}",
                canonical.display(),
                canonical_rootfs.display()
            )
            .into());
        }
        path_filter = Some(normalize_relative_path(path));
        rootfs_candidates.push("/".to_string());
        files_skipped += collect_files(&canonical, &mut files);
    } else {
        let candidate_roots = if discover_rootfs {
            let mut discovered = discover_rootfs_candidates(canonical_rootfs, &mut files_skipped);
            if looks_like_rootfs(canonical_rootfs) {
                discovered.insert(0, canonical_rootfs.to_path_buf());
            }

            if discovered.is_empty() {
                vec![canonical_rootfs.to_path_buf()]
            } else {
                discovered
            }
        } else {
            vec![canonical_rootfs.to_path_buf()]
        };

        rootfs_candidates = candidate_roots
            .iter()
            .map(|candidate| rootfs_relative(canonical_rootfs, candidate))
            .collect();

        for candidate_root in candidate_roots {
            if all_files {
                files_skipped += collect_files(&candidate_root, &mut files);
            } else {
                files_skipped += collect_files_from_candidate_root(&candidate_root, &mut files);
            }
        }
    }

    files.sort();
    files.dedup();
    Ok((files, files_skipped, path_filter, rootfs_candidates))
}

fn collect_files(root: &Path, files: &mut Vec<PathBuf>) -> usize {
    let mut skipped = 0usize;

    if root.is_file() {
        files.push(root.to_path_buf());
        return skipped;
    }

    if !root.is_dir() {
        return skipped + 1;
    }

    for entry in WalkDir::new(root).follow_links(false) {
        let Ok(entry) = entry else {
            skipped += 1;
            continue;
        };
        if entry.file_type().is_file() {
            files.push(entry.path().to_path_buf());
        }
    }

    skipped
}

fn collect_files_from_candidate_root(root: &Path, files: &mut Vec<PathBuf>) -> usize {
    let mut skipped = 0usize;

    for dir in DEFAULT_BINARY_DIRS {
        let full = root.join(dir);
        if !full.exists() {
            continue;
        }

        let canonical = match full.canonicalize() {
            Ok(path) => path,
            Err(_) => {
                skipped += 1;
                continue;
            }
        };

        if !canonical.starts_with(root) {
            skipped += 1;
            continue;
        }

        skipped += collect_files(&canonical, files);
    }

    skipped
}

fn discover_rootfs_candidates(canonical_rootfs: &Path, files_skipped: &mut usize) -> Vec<PathBuf> {
    let mut candidates = Vec::new();
    let mut walker = WalkDir::new(canonical_rootfs)
        .follow_links(false)
        .max_depth(DISCOVERY_MAX_DEPTH)
        .into_iter();

    while let Some(entry) = walker.next() {
        let entry = match entry {
            Ok(entry) => entry,
            Err(_) => {
                *files_skipped += 1;
                continue;
            }
        };

        if entry.depth() == 0 || !entry.file_type().is_dir() {
            continue;
        }

        if should_skip_discovery_dir(entry.file_name()) {
            walker.skip_current_dir();
            continue;
        }

        if looks_like_rootfs(entry.path()) {
            candidates.push(entry.path().to_path_buf());
        }
    }

    candidates.sort();
    candidates.dedup();
    candidates
}

fn should_skip_discovery_dir(name: &std::ffi::OsStr) -> bool {
    let Some(name) = name.to_str() else {
        return false;
    };

    DISCOVERY_SKIP_DIRS.contains(&name)
}

fn looks_like_rootfs(path: &Path) -> bool {
    if !path.is_dir() {
        return false;
    }

    let marker_count = ROOTFS_MARKER_DIRS
        .iter()
        .filter(|dir| is_real_dir(&path.join(dir)))
        .count();
    let has_bin = is_real_dir(&path.join("bin"));
    let has_lib = is_real_dir(&path.join("lib"));

    if marker_count >= 2 || (has_bin && has_lib) {
        return true;
    }

    if has_predictable_elfs(path) {
        return true;
    }

    is_rootfs_name_hint(path) && marker_count >= 1
}

fn has_predictable_elfs(path: &Path) -> bool {
    ROOTFS_ELF_DIRS.iter().any(|dir| {
        let full = path.join(dir);
        is_real_dir(&full) && contains_elf_file(&full)
    })
}

fn contains_elf_file(root: &Path) -> bool {
    for entry in WalkDir::new(root)
        .follow_links(false)
        .max_depth(DISCOVERY_MAX_DEPTH)
    {
        let Ok(entry) = entry else {
            continue;
        };

        if !entry.file_type().is_file() {
            continue;
        }

        if is_elf_file(entry.path()) {
            return true;
        }
    }

    false
}

fn is_elf_file(path: &Path) -> bool {
    let Ok(mut file) = fs::File::open(path) else {
        return false;
    };
    let mut magic = [0u8; 4];
    use std::io::Read;
    file.read_exact(&mut magic).is_ok() && magic == *b"\x7fELF"
}

fn is_rootfs_name_hint(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| ROOTFS_NAME_HINTS.contains(&name))
        .unwrap_or(false)
}

fn is_real_dir(path: &Path) -> bool {
    fs::symlink_metadata(path)
        .map(|metadata| metadata.file_type().is_dir())
        .unwrap_or(false)
}

fn extract_strings(bytes: &[u8], min_len: usize, mode: ExtractionMode) -> Vec<ExtractedString> {
    match mode {
        ExtractionMode::PrintableStrings => extract_printable_strings(bytes, min_len),
        ExtractionMode::TextLines => extract_text_lines(bytes, min_len),
    }
}

fn extract_printable_strings(bytes: &[u8], min_len: usize) -> Vec<ExtractedString> {
    let mut extracted = Vec::new();
    let mut current = String::new();
    let mut next_index = 0usize;
    let mut current_start_offset = 0usize;
    let mut current_start_line = 1usize;
    let mut line_number = 1usize;

    for (offset, &byte) in bytes.iter().enumerate() {
        if is_string_byte(byte) {
            if current.is_empty() {
                current_start_offset = offset;
                current_start_line = line_number;
            }
            current.push(byte as char);
            continue;
        }

        flush_extracted_string(
            &mut current,
            min_len,
            &mut extracted,
            &mut next_index,
            current_start_offset,
            current_start_line,
        );
        if byte == b'\n' {
            line_number = line_number.saturating_add(1);
        }
    }

    flush_extracted_string(
        &mut current,
        min_len,
        &mut extracted,
        &mut next_index,
        current_start_offset,
        current_start_line,
    );
    extracted
}

fn extract_text_lines(bytes: &[u8], min_len: usize) -> Vec<ExtractedString> {
    let mut extracted = Vec::new();
    let mut next_index = 0usize;
    let mut line_start = 0usize;
    let mut line_number = 1usize;

    for (offset, &byte) in bytes.iter().enumerate() {
        if byte == b'\n' {
            flush_text_line(
                &bytes[line_start..offset],
                min_len,
                &mut extracted,
                &mut next_index,
                line_start,
                line_number,
            );
            line_start = offset.saturating_add(1);
            line_number = line_number.saturating_add(1);
        }
    }

    if line_start <= bytes.len() {
        flush_text_line(
            &bytes[line_start..],
            min_len,
            &mut extracted,
            &mut next_index,
            line_start,
            line_number,
        );
    }

    extracted
}

fn evaluate_file_matches(
    extracted: &[ExtractedString],
    include: Option<&Regex>,
    profiles: &[Regex],
    excludes: &[Regex],
    max: usize,
    context: usize,
    unique: bool,
    min_strength: &str,
    context_filter: &str,
    extraction_mode: ExtractionMode,
) -> FileEvaluation {
    let mut candidates = Vec::new();
    let mut seen_values = HashSet::new();

    for item in extracted {
        let include_match = include
            .map(|regex| regex.is_match(&item.value))
            .unwrap_or(false);
        let profile_match = profiles.iter().any(|regex| regex.is_match(&item.value));
        let excluded = excludes.iter().any(|regex| regex.is_match(&item.value));

        let classification = classify_match(&item.value);
        if !(include_match || profile_match)
            || excluded
            || !strength_meets(classification.strength, min_strength)
        {
            continue;
        }

        if unique && !seen_values.insert(item.value.clone()) {
            continue;
        }

        candidates.push(item);
    }

    let matched_values = candidates
        .iter()
        .map(|hit| hit.value.clone())
        .collect::<HashSet<String>>();
    let unique_match_count = matched_values.len();
    let match_count = candidates.len();
    let truncated = candidates.len() > max;
    let score = candidates
        .iter()
        .map(|hit| classify_match(&hit.value).score)
        .sum::<usize>();
    let path_literal_count = candidates
        .iter()
        .filter(|hit| classify_match(&hit.value).kind == MatchKind::LiteralPath)
        .count();
    let accessor_count = candidates
        .iter()
        .filter(|hit| classify_match(&hit.value).kind == MatchKind::Accessor)
        .count();
    let strength = file_strength(score, path_literal_count, accessor_count).to_string();
    let strings: Vec<StringMatch> = candidates
        .into_iter()
        .take(max)
        .map(|item| {
            let before_start = item.index.saturating_sub(context);
            let after_end = item
                .index
                .saturating_add(context)
                .saturating_add(1)
                .min(extracted.len());
            let context_before = extracted[before_start..item.index]
                .iter()
                .filter(|entry| !matched_values.contains(&entry.value))
                .filter(|entry| !is_filtered_context(&entry.value, context_filter))
                .map(|entry| {
                    display_value_for_match(&entry.value, include, profiles, extraction_mode, false)
                })
                .collect();
            let context_after = extracted[item.index + 1..after_end]
                .iter()
                .filter(|entry| !matched_values.contains(&entry.value))
                .filter(|entry| !is_filtered_context(&entry.value, context_filter))
                .map(|entry| {
                    display_value_for_match(&entry.value, include, profiles, extraction_mode, false)
                })
                .collect();
            let classification = classify_match(&item.value);
            StringMatch {
                value: display_value_for_match(
                    &item.value,
                    include,
                    profiles,
                    extraction_mode,
                    true,
                ),
                offset: item.offset,
                line_number: item.line_number,
                kind: classification.kind.as_str().to_string(),
                strength: classification.strength.to_string(),
                score: classification.score,
                context_before,
                context_after,
            }
        })
        .collect();

    FileEvaluation {
        strings,
        match_count,
        unique_match_count,
        matched_values,
        truncated,
        score,
        strength,
        path_literal_count,
        accessor_count,
    }
}

fn flush_extracted_string(
    current: &mut String,
    min_len: usize,
    extracted: &mut Vec<ExtractedString>,
    next_index: &mut usize,
    start_offset: usize,
    start_line: usize,
) {
    if current.is_empty() {
        return;
    }

    let candidate = std::mem::take(current);
    if candidate.len() < min_len {
        return;
    }

    extracted.push(ExtractedString {
        index: *next_index,
        offset: start_offset,
        line_number: start_line,
        value: candidate,
    });
    *next_index += 1;
}

fn flush_text_line(
    line: &[u8],
    min_len: usize,
    extracted: &mut Vec<ExtractedString>,
    next_index: &mut usize,
    start_offset: usize,
    line_number: usize,
) {
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    let value = line
        .iter()
        .copied()
        .filter(|byte| is_string_byte(*byte))
        .map(char::from)
        .collect::<String>();

    if value.len() < min_len {
        return;
    }

    extracted.push(ExtractedString {
        index: *next_index,
        offset: start_offset,
        line_number,
        value,
    });
    *next_index += 1;
}

fn is_string_byte(byte: u8) -> bool {
    byte == b' ' || byte == b'\t' || byte.is_ascii_graphic()
}

fn is_text_byte(byte: u8) -> bool {
    matches!(byte, b'\n' | b'\r') || is_string_byte(byte)
}

fn is_probably_text_content(bytes: &[u8]) -> bool {
    if bytes.is_empty() {
        return true;
    }

    let sample = &bytes[..bytes.len().min(TEXT_DETECTION_SAMPLE_BYTES)];
    if sample.contains(&0) {
        return false;
    }

    let text_like = sample.iter().filter(|byte| is_text_byte(**byte)).count();
    (text_like as f64 / sample.len() as f64) >= TEXT_DETECTION_MIN_RATIO
}

fn display_value_for_match(
    value: &str,
    include: Option<&Regex>,
    profiles: &[Regex],
    extraction_mode: ExtractionMode,
    match_centered: bool,
) -> String {
    if extraction_mode != ExtractionMode::TextLines {
        return value.to_string();
    }

    let focus = if match_centered {
        first_match_span(value, include, profiles)
    } else {
        None
    };
    clip_text_snippet(value, focus)
}

fn first_match_span(
    value: &str,
    include: Option<&Regex>,
    profiles: &[Regex],
) -> Option<(usize, usize)> {
    let include_match = include.and_then(|regex| regex.find(value));
    let profile_match = profiles
        .iter()
        .filter_map(|regex| regex.find(value))
        .min_by(|left, right| {
            left.start()
                .cmp(&right.start())
                .then_with(|| left.end().cmp(&right.end()))
        });

    match (include_match, profile_match) {
        (Some(left), Some(right)) => {
            if left.start() <= right.start() {
                Some((left.start(), left.end()))
            } else {
                Some((right.start(), right.end()))
            }
        }
        (Some(found), None) | (None, Some(found)) => Some((found.start(), found.end())),
        (None, None) => None,
    }
}

fn clip_text_snippet(value: &str, focus: Option<(usize, usize)>) -> String {
    if value.len() <= TEXT_SNIPPET_LIMIT {
        return value.to_string();
    }

    let (focus_start, focus_end) = focus.unwrap_or((0, 0));
    let match_center = if focus_end > focus_start {
        focus_start + (focus_end - focus_start) / 2
    } else {
        0
    };
    let mut start = match_center.saturating_sub(TEXT_SNIPPET_LIMIT / 2);
    let mut end = (start + TEXT_SNIPPET_LIMIT).min(value.len());
    if end - start < TEXT_SNIPPET_LIMIT {
        start = end.saturating_sub(TEXT_SNIPPET_LIMIT);
    }

    start = clamp_char_boundary_start(value, start);
    end = clamp_char_boundary_end(value, end);

    let mut snippet = String::new();
    if start > 0 {
        snippet.push_str("...");
    }
    snippet.push_str(value[start..end].trim());
    if end < value.len() {
        snippet.push_str("...");
    }
    snippet
}

fn clamp_char_boundary_start(value: &str, mut index: usize) -> usize {
    while index > 0 && !value.is_char_boundary(index) {
        index -= 1;
    }
    index
}

fn clamp_char_boundary_end(value: &str, mut index: usize) -> usize {
    while index < value.len() && !value.is_char_boundary(index) {
        index += 1;
    }
    index.min(value.len())
}

fn is_elf_bytes(bytes: &[u8]) -> bool {
    bytes.len() >= 4 && bytes[..4] == *b"\x7fELF"
}

fn validate_relative_path(path: &Path) -> DynResult<()> {
    if path.is_absolute() {
        return Err(format!("--path must be relative to rootfs: {}", path.display()).into());
    }

    for component in path.components() {
        match component {
            Component::Normal(_) | Component::CurDir => {}
            _ => {
                return Err(format!(
                    "--path must be relative to rootfs and must not contain '..': {}",
                    path.display()
                )
                .into())
            }
        }
    }

    Ok(())
}

fn normalize_relative_path(path: &Path) -> String {
    path.components()
        .filter_map(|component| match component {
            Component::Normal(part) => Some(part.to_string_lossy().to_string()),
            Component::CurDir => None,
            _ => None,
        })
        .collect::<Vec<_>>()
        .join("/")
}

fn rootfs_relative(rootfs: &Path, path: &Path) -> String {
    let rel = path.strip_prefix(rootfs).unwrap_or(path);
    format!("/{}", rel.to_string_lossy().replace('\\', "/"))
}

fn build_ranked_files(matches: &[FileMatches]) -> Vec<RankedFileMatch> {
    let mut ranked_files = matches
        .iter()
        .map(|file| RankedFileMatch {
            path: file.path.clone(),
            match_count: file.match_count,
            unique_match_count: file.unique_match_count,
            score: file.score,
            strength: file.strength.clone(),
            path_literal_count: file.path_literal_count,
            accessor_count: file.accessor_count,
            size_bytes: file.size_bytes,
            truncated: file.truncated,
        })
        .collect::<Vec<_>>();

    ranked_files.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| right.match_count.cmp(&left.match_count))
            .then_with(|| right.unique_match_count.cmp(&left.unique_match_count))
            .then_with(|| left.path.cmp(&right.path))
    });
    ranked_files
}

fn build_shared_strings(matches: &[FileMatches]) -> Vec<SharedStringMatch> {
    let mut files_by_value: HashMap<String, HashSet<String>> = HashMap::new();

    for file in matches {
        for value in &file.matched_values {
            files_by_value
                .entry(value.clone())
                .or_default()
                .insert(file.path.clone());
        }
    }

    let mut shared_strings = files_by_value
        .into_iter()
        .filter_map(|(value, files)| {
            if files.len() < 2 {
                return None;
            }

            let mut files = files.into_iter().collect::<Vec<_>>();
            files.sort();
            Some(SharedStringMatch {
                value,
                file_count: files.len(),
                files,
            })
        })
        .collect::<Vec<_>>();

    shared_strings.sort_by(|left, right| {
        left.file_count
            .cmp(&right.file_count)
            .then_with(|| left.value.cmp(&right.value))
    });
    shared_strings
}

fn render_report(report: &SearchReport, palette: &Palette, request: &SearchRequest<'_>) {
    if palette.enabled() {
        render_report_panel(report, palette, request);
    } else {
        render_report_plain(report, palette, request);
    }
}

/// Panel-mode rendering: verdict line, `●` per file with dimmed match
/// metadata, hit detail capped at 10 per file with a `… N more` tail.
fn render_report_panel(report: &SearchReport, palette: &Palette, request: &SearchRequest<'_>) {
    const MAX_HITS_PER_FILE: usize = 10;

    let total_matches: usize = report.matches.iter().map(|file| file.match_count).sum();
    let mut lines = Vec::new();
    if report.matches.is_empty() {
        lines.push(format!(
            "{} {}",
            palette.dot_muted(),
            palette.muted(format!(
                "no matches for pattern {}",
                if report.include.is_empty() {
                    "(none)"
                } else {
                    &report.include
                }
            ))
        ));
        lines.push(palette.muted(format!(
            "{} files scanned across {}",
            report.files_scanned,
            compact_scope(report)
        )));
        println!("{}", palette.panel("fat search", &lines));
        println!(
            "{}",
            palette.next_hint("fat search --all-files --include <pattern> to widen the scope")
        );
        return;
    }

    lines.push(format!(
        "{} {}",
        palette.check_glyph(true),
        palette.good(format!(
            "{} match{} in {} file{}",
            total_matches,
            if total_matches == 1 { "" } else { "es" },
            report.files_with_matches,
            if report.files_with_matches == 1 {
                ""
            } else {
                "s"
            }
        ))
    ));
    lines.push(palette.muted(format!("scope: {}", compact_scope(report))));
    lines.push(palette.muted(format!(
        "pattern: {}",
        if report.include.is_empty() {
            "(none)"
        } else {
            &report.include
        }
    )));

    for ranked in &report.ranked_files {
        let Some(file) = report
            .matches
            .iter()
            .find(|candidate| candidate.path == ranked.path)
        else {
            continue;
        };
        lines.push(String::new());
        let dot = match file.strength.as_str() {
            "STRONG" => palette.dot_ok(),
            "MEDIUM" => palette.dot_warn(),
            _ => palette.dot_muted(),
        };
        let mut meta = format!(
            "path {} · {} · score={} · hits={}{} · size={}",
            display_parent_path(&file.path).unwrap_or_else(|| "/".to_string()),
            file.strength,
            file.score,
            file.match_count,
            unique_suffix(file.match_count, file.unique_match_count),
            format_size(file.size_bytes),
        );
        if file.truncated {
            meta.push_str(&format!(
                " · showing first {} of {}",
                file.strings.len(),
                file.match_count
            ));
        }
        lines.push(format!(
            "{} {}  {}",
            dot,
            palette.key(display_file_name(&file.path)),
            palette.muted(meta)
        ));
        for kind in ["literal-path", "accessor", "substring"] {
            let hits = file
                .strings
                .iter()
                .filter(|hit| hit.kind == kind)
                .collect::<Vec<_>>();
            if hits.is_empty() {
                continue;
            }
            lines.push(palette.muted(format!("· [{kind}]")));
            for hit in hits.iter().take(MAX_HITS_PER_FILE) {
                lines.push(format!(
                    "· @ 0x{:08x}  {}",
                    hit.offset,
                    palette.code(display_search_string(&hit.value))
                ));
                if !hit.context_before.is_empty() || !hit.context_after.is_empty() {
                    lines.push(palette.muted("· nearby:"));
                    for (index, before) in hit.context_before.iter().rev().enumerate() {
                        lines.push(palette.muted(format!(
                            "· -{}  {}",
                            index + 1,
                            display_search_string(before)
                        )));
                    }
                    for (index, after) in hit.context_after.iter().enumerate() {
                        lines.push(palette.muted(format!(
                            "· +{}  {}",
                            index + 1,
                            display_search_string(after)
                        )));
                    }
                }
            }
            if hits.len() > MAX_HITS_PER_FILE {
                lines.push(palette.muted(format!("· … {} more", hits.len() - MAX_HITS_PER_FILE)));
            }
        }
    }

    if !report.ranked_files.is_empty() {
        lines.push(String::new());
        lines.push(palette.heading("Ranked files"));
        let prefix =
            common_parent_prefix(report.ranked_files.iter().map(|file| file.path.as_str()));
        if let Some(prefix) = &prefix {
            if !prefix.is_empty() {
                lines.push(palette.muted(format!("under {}/", prefix.trim_start_matches('/'))));
            }
        }
        for (index, file) in report.ranked_files.iter().enumerate() {
            let display_path = shorten_with_prefix(&file.path, prefix.as_deref());
            lines.push(format!(
                "{} {}  {}",
                palette.dot_ok(),
                display_path,
                palette.muted(format!(
                    "{} · score={} · hits={}{} · size={}{}",
                    file.strength,
                    file.score,
                    file.match_count,
                    unique_suffix(file.match_count, file.unique_match_count),
                    format_size(file.size_bytes),
                    if file.truncated { " truncated" } else { "" }
                ))
            ));
            let _ = index;
        }
    }

    let signals = string_signals(report);
    let threshold = discriminating_threshold(report.files_with_matches);
    let discriminating = signals
        .iter()
        .filter(|signal| signal.file_count <= threshold)
        .collect::<Vec<_>>();
    let common = signals
        .iter()
        .filter(|signal| signal.file_count > threshold)
        .collect::<Vec<_>>();
    for (title, group, limit) in [
        ("Discriminating strings", discriminating, 10usize),
        ("Common strings", common, usize::MAX),
    ] {
        if group.is_empty() {
            continue;
        }
        lines.push(String::new());
        lines.push(palette.heading(title));
        let shown = group.iter().take(limit).copied().collect::<Vec<_>>();
        let single_file = common_signal_file(&shown);
        if let Some(path) = &single_file {
            lines.push(palette.muted(format!("from {path}")));
        }
        for signal in shown {
            let value = display_search_string(&signal.value);
            if single_file.is_some() {
                lines.push(value);
            } else {
                lines.push(format!(
                    "{} {}",
                    value,
                    palette.muted(format!(
                        "(files: {}, {})",
                        signal.file_count,
                        signal.files.join(", ")
                    ))
                ));
            }
        }
    }

    if request.show_empty && !report.scanned_files_without_matches.is_empty() {
        lines.push(String::new());
        lines.push(palette.heading("Files without matches"));
        for path in &report.scanned_files_without_matches {
            lines.push(palette.muted(path.clone()));
        }
    }

    println!("{}", palette.panel("fat search", &lines));
    let top = report.ranked_files.first().map(|file| file.path.clone());
    match top.and_then(|path| display_parent_path(&path)) {
        Some(parent) => println!(
            "{}",
            palette.next_hint(&format!(
                "fat search --path {parent} --include <pattern> to narrow the scope"
            ))
        ),
        None => println!(
            "{}",
            palette.next_hint("fat search --all-files --include <pattern> to widen the scope")
        ),
    }
}

/// Plain rendering; byte-identical to the historical output so scripts and
/// piped output keep parsing the same shape (match hits uncapped here).
fn render_report_plain(report: &SearchReport, palette: &Palette, request: &SearchRequest<'_>) {
    if request.verbose {
        render_verbose_header(report);
    } else {
        println!("{}", compact_header(report));
    }

    if report.matches.is_empty() {
        println!("No matches found.");
        return;
    }

    println!();
    println!("Results");
    for (index, ranked) in report.ranked_files.iter().enumerate() {
        let Some(file) = report
            .matches
            .iter()
            .find(|candidate| candidate.path == ranked.path)
        else {
            continue;
        };
        if index > 0 {
            println!();
        }
        println!("{}", palette.muted(SEARCH_SECTION_DIVIDER));
        println!(
            "{}. {}",
            index + 1,
            palette.key(display_file_name(&file.path))
        );
        if let Some(parent) = display_parent_path(&file.path) {
            println!("   {}", palette.muted(format!("path {parent}")));
        }
        println!(
            "   strength {}   score={}   hits={}{}   size={}",
            palette.status_word(&file.strength),
            file.score,
            file.match_count,
            unique_suffix(file.match_count, file.unique_match_count),
            format_size(file.size_bytes),
        );
        render_grouped_hits(file, palette);
        if file.truncated {
            println!(
                "{}",
                palette.muted(format!(
                    "... showing first {} of {} matches",
                    file.strings.len(),
                    file.match_count
                ))
            );
        }
    }

    render_ranked_files(report, palette);
    render_string_signal_blocks(report, palette);
    if request.show_empty {
        render_empty_scanned_files(report);
    }
}

fn render_verbose_header(report: &SearchReport) {
    println!("Search report");
    println!("  Rootfs: {}", report.rootfs_path);
    println!(
        "  Rootfs candidates: {}",
        if report.rootfs_candidates.is_empty() {
            "(none)".to_string()
        } else {
            report.rootfs_candidates.join(", ")
        }
    );
    println!(
        "  Discover rootfs: {}",
        if report.discover_rootfs { "yes" } else { "no" }
    );
    println!(
        "  Case insensitive: {}",
        if report.case_insensitive { "yes" } else { "no" }
    );
    if report.profiles.is_empty() {
        println!("  Profiles: (none)");
    } else {
        println!("  Profiles: {}", report.profiles.join(", "));
    }
    println!("  Scope: {}", report.scope);
    if report.include.is_empty() {
        println!("  Include: (none)");
    } else {
        println!("  Include: {}", report.include);
    }
    if let Some(path_filter) = &report.path_filter {
        println!("  Path filter: {path_filter}");
    }
    if report.exclude.is_empty() {
        println!("  Exclude: (none)");
    } else {
        println!("  Exclude: {}", report.exclude.join(", "));
    }
    println!("  Min len: {}", report.min_len);
    println!("  Max per file: {}", report.max_per_file);
    println!(
        "  Files: scanned {}, skipped {}, with matches {}",
        report.files_scanned, report.files_skipped, report.files_with_matches
    );
}

fn compact_header(report: &SearchReport) -> String {
    format!(
        "Search\n  scope    {}\n  pattern  {}\n  matched  {}/{} files",
        compact_scope(report),
        if report.include.is_empty() {
            "(none)"
        } else {
            &report.include
        },
        report.files_with_matches,
        report.files_scanned
    )
}

fn compact_scope(report: &SearchReport) -> String {
    let scope = if report.scope == "all-files" {
        "all files"
    } else {
        "ELF"
    };
    match &report.path_filter {
        Some(path) => format!("{scope} under {path}"),
        None if report.scope == "elf-binaries" => "ELF binaries".to_string(),
        None => scope.to_string(),
    }
}

fn render_grouped_hits(file: &FileMatches, palette: &Palette) {
    for kind in ["literal-path", "accessor", "substring"] {
        let hits = file
            .strings
            .iter()
            .filter(|hit| hit.kind == kind)
            .collect::<Vec<_>>();
        if hits.is_empty() {
            continue;
        }
        println!("  [{kind}]");
        for hit in hits {
            println!(
                "    @ 0x{:08x}  {}",
                hit.offset,
                palette.bad(display_search_string(&hit.value))
            );
            render_nearby_strings(hit, palette);
        }
    }
}

fn render_nearby_strings(hit: &StringMatch, palette: &Palette) {
    if hit.context_before.is_empty() && hit.context_after.is_empty() {
        return;
    }
    println!("{}", palette.muted("      Nearby strings by offset:"));
    for (index, before) in hit.context_before.iter().rev().enumerate() {
        println!(
            "{}",
            palette.muted(format!(
                "        -{}  {}",
                index + 1,
                display_search_string(before)
            ))
        );
    }
    for (index, after) in hit.context_after.iter().enumerate() {
        println!(
            "{}",
            palette.muted(format!(
                "        +{}  {}",
                index + 1,
                display_search_string(after)
            ))
        );
    }
}

fn display_search_string(value: &str) -> String {
    let demangled = crate::r2_triage_cmd::demangle_cpp_symbol(value);
    if demangled != value {
        return demangled;
    }
    demangle_search_string_with_cxxfilt(value).unwrap_or_else(|| value.to_string())
}

fn demangle_search_string_with_cxxfilt(value: &str) -> Option<String> {
    if !value.starts_with("_Z") {
        return None;
    }
    let output = Command::new("c++filt").arg(value).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let demangled = String::from_utf8(output.stdout).ok()?.trim().to_string();
    if demangled.is_empty() || demangled == value {
        None
    } else {
        Some(demangled)
    }
}

fn render_ranked_files(report: &SearchReport, palette: &Palette) {
    if report.ranked_files.is_empty() {
        return;
    }
    println!();
    println!("Ranked files");
    let prefix = common_parent_prefix(report.ranked_files.iter().map(|file| file.path.as_str()));
    if let Some(prefix) = &prefix {
        if !prefix.is_empty() {
            println!("  under {}/", prefix.trim_start_matches('/'));
        }
    }
    for (index, file) in report.ranked_files.iter().enumerate() {
        let display_path = shorten_with_prefix(&file.path, prefix.as_deref());
        println!("  {}. {}", index + 1, palette.key(display_path));
        println!(
            "     strength {}   score={}   hits={}{}   size={}{}",
            palette.status_word(&file.strength),
            file.score,
            file.match_count,
            unique_suffix(file.match_count, file.unique_match_count),
            format_size(file.size_bytes),
            if file.truncated { " truncated" } else { "" }
        );
    }
}

fn render_string_signal_blocks(report: &SearchReport, palette: &Palette) {
    let signals = string_signals(report);
    let threshold = discriminating_threshold(report.files_with_matches);
    let discriminating = signals
        .iter()
        .filter(|signal| signal.file_count <= threshold)
        .collect::<Vec<_>>();
    if !discriminating.is_empty() {
        println!();
        println!("Discriminating strings");
        render_signal_lines(&discriminating, 10, palette);
    }

    let common = signals
        .iter()
        .filter(|signal| signal.file_count > threshold)
        .collect::<Vec<_>>();
    if !common.is_empty() {
        println!();
        println!("Common strings");
        render_signal_lines(&common, usize::MAX, palette);
    }
}

fn render_signal_lines(signals: &[&SharedStringMatch], limit: usize, palette: &Palette) {
    let shown = signals.iter().take(limit).copied().collect::<Vec<_>>();
    let single_file = common_signal_file(&shown);
    if let Some(path) = &single_file {
        println!("  from {}", palette.key(path));
    }

    for signal in shown {
        let value = display_search_string(&signal.value);
        if single_file.is_some() {
            println!("  {value}");
        } else {
            println!(
                "  {} (files: {}, {})",
                value,
                signal.file_count,
                signal.files.join(", ")
            );
        }
    }
}

fn display_file_name(path: &str) -> &str {
    path.trim_end_matches('/')
        .rsplit('/')
        .next()
        .filter(|part| !part.is_empty())
        .unwrap_or(path)
}

fn display_parent_path(path: &str) -> Option<String> {
    let trimmed = path.trim_end_matches('/');
    let (parent, _) = trimmed.rsplit_once('/')?;
    if parent.is_empty() {
        Some("/".to_string())
    } else {
        Some(format!("{parent}/"))
    }
}

fn common_signal_file(signals: &[&SharedStringMatch]) -> Option<String> {
    let mut iter = signals.iter();
    let first = iter.next()?;
    if first.file_count != 1 || first.files.len() != 1 {
        return None;
    }
    let path = first.files[0].clone();
    if iter
        .all(|signal| signal.file_count == 1 && signal.files.len() == 1 && signal.files[0] == path)
    {
        Some(path)
    } else {
        None
    }
}

fn render_empty_scanned_files(report: &SearchReport) {
    if report.scanned_files_without_matches.is_empty() {
        return;
    }
    println!();
    println!("Files without matches");
    for path in &report.scanned_files_without_matches {
        println!("  {path}");
    }
}

fn render_summary_report(report: &SearchReport, palette: &Palette) {
    if !palette.enabled() {
        for ranked in &report.ranked_files {
            let Some(file) = report
                .matches
                .iter()
                .find(|candidate| candidate.path == ranked.path)
            else {
                continue;
            };
            println!(
                "{:<18} {:<6} {}",
                file.path
                    .trim_start_matches('/')
                    .rsplit('/')
                    .next()
                    .unwrap_or(file.path.as_str()),
                palette.status_word(&file.strength),
                summary_reason(file)
            );
        }
        return;
    }

    let total_matches: usize = report.matches.iter().map(|file| file.match_count).sum();
    let mut lines = Vec::new();
    if report.ranked_files.is_empty() {
        lines.push(format!(
            "{} {}",
            palette.dot_muted(),
            palette.muted("no matches"),
        ));
    } else {
        lines.push(format!(
            "{} {}",
            palette.check_glyph(true),
            palette.good(format!(
                "{} match{} in {} file{}",
                total_matches,
                if total_matches == 1 { "" } else { "es" },
                report.files_with_matches,
                if report.files_with_matches == 1 {
                    ""
                } else {
                    "s"
                }
            ))
        ));
    }
    for ranked in &report.ranked_files {
        let Some(file) = report
            .matches
            .iter()
            .find(|candidate| candidate.path == ranked.path)
        else {
            continue;
        };
        let dot = match file.strength.as_str() {
            "STRONG" => palette.dot_ok(),
            "MEDIUM" => palette.dot_warn(),
            _ => palette.dot_muted(),
        };
        lines.push(format!(
            "{} {}  {}",
            dot,
            file.path
                .trim_start_matches('/')
                .rsplit('/')
                .next()
                .unwrap_or(file.path.as_str()),
            palette.muted(format!("{} · {}", file.strength, summary_reason(file)))
        ));
    }
    println!("{}", palette.panel("Search Summary", &lines));
}

fn render_anchor_report(report: &SearchReport) {
    for file in &report.matches {
        for hit in &file.strings {
            println!("<!-- anchor");
            println!("uri: {}", file.path.trim_start_matches('/'));
            if file.file_kind == "text" && hit.line_number > 0 {
                println!(
                    "region: {{ stringOffset: 0x{:x}, line: {}, value: \"{}\" }}",
                    hit.offset,
                    hit.line_number,
                    escape_anchor_value(&hit.value)
                );
            } else {
                println!(
                    "region: {{ stringOffset: 0x{:x}, value: \"{}\" }}",
                    hit.offset,
                    escape_anchor_value(&hit.value)
                );
            }
            println!("label: {}", anchor_label(&file.path, hit.offset));
            println!("-->");
        }
    }
}

fn unique_suffix(match_count: usize, unique_match_count: usize) -> String {
    if match_count == unique_match_count {
        String::new()
    } else {
        format!(" unique={unique_match_count}")
    }
}

fn format_size(size: u64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = 1024.0 * 1024.0;
    let size = size as f64;
    if size >= MB {
        format!("{:.1} MB", size / MB)
    } else if size >= KB {
        format!("{:.0} KB", size / KB)
    } else {
        format!("{} bytes", size as u64)
    }
}

fn common_parent_prefix<'a>(paths: impl Iterator<Item = &'a str>) -> Option<String> {
    let mut parents = paths
        .filter_map(|path| path.rsplit_once('/').map(|(parent, _)| parent.to_string()))
        .collect::<Vec<_>>();
    if parents.is_empty() {
        return None;
    }
    parents.sort();
    parents.dedup();
    let mut prefix = parents.first()?.clone();
    for parent in parents.iter().skip(1) {
        while !parent.starts_with(&prefix) {
            let (next, _) = prefix.rsplit_once('/')?;
            prefix = next.to_string();
        }
    }
    if prefix.is_empty() {
        None
    } else {
        Some(prefix)
    }
}

fn shorten_with_prefix(path: &str, prefix: Option<&str>) -> String {
    match prefix {
        Some(prefix) if !prefix.is_empty() && path.starts_with(prefix) => path
            .trim_start_matches(prefix)
            .trim_start_matches('/')
            .to_string(),
        _ => path.to_string(),
    }
}

fn string_signals(report: &SearchReport) -> Vec<SharedStringMatch> {
    let mut files_by_value: HashMap<String, HashSet<String>> = HashMap::new();
    for file in &report.matches {
        for value in &file.matched_values {
            files_by_value
                .entry(value.clone())
                .or_default()
                .insert(file.path.clone());
        }
    }
    let mut signals = files_by_value
        .into_iter()
        .map(|(value, files)| {
            let mut files = files.into_iter().collect::<Vec<_>>();
            files.sort();
            SharedStringMatch {
                value,
                file_count: files.len(),
                files,
            }
        })
        .collect::<Vec<_>>();
    signals.sort_by(|left, right| {
        left.file_count
            .cmp(&right.file_count)
            .then_with(|| left.value.cmp(&right.value))
    });
    signals
}

fn discriminating_threshold(files_with_matches: usize) -> usize {
    (files_with_matches / 2).max(1)
}

fn summary_reason(file: &FileMatches) -> String {
    let mut parts = Vec::new();
    if file.path_literal_count > 0 {
        parts.push("path-ref".to_string());
    }
    if file.accessor_count > 0 {
        parts.push(format!(
            "{} accessor{}",
            file.accessor_count,
            if file.accessor_count == 1 { "" } else { "s" }
        ));
    }
    let substring_count = file
        .match_count
        .saturating_sub(file.path_literal_count)
        .saturating_sub(file.accessor_count);
    if substring_count > 0 {
        parts.push(format!(
            "{} substring{}",
            substring_count,
            if substring_count == 1 { "" } else { "s" }
        ));
    }
    if parts.is_empty() {
        parts.push(format!("{} matches", file.match_count));
    }
    parts.join(" + ")
}

fn escape_anchor_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}

fn anchor_label(path: &str, offset: usize) -> String {
    let file_name = path
        .trim_start_matches('/')
        .rsplit('/')
        .next()
        .unwrap_or(path.trim_start_matches('/'));
    format!("{file_name}@0x{offset:x}")
}
