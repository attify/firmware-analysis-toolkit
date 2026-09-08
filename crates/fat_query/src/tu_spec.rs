use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::ffi::OsStr;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TUSpec {
    pub file: PathBuf,
    pub directory: PathBuf,
    pub arguments: Vec<String>,
    pub command: Option<String>,
    pub output: Option<PathBuf>,
    pub source: TUSpecSource,
    pub selection_reason: String,
    pub hash: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum TUSpecSource {
    CompileCommands,
    CodeQlExtractionCommands,
    CompileFlags,
    FixtureMetadata,
    Synthesized,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct CompileCommandEntry {
    directory: PathBuf,
    file: PathBuf,
    #[serde(default)]
    arguments: Vec<String>,
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    output: Option<PathBuf>,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
struct FixtureTuSpec {
    file: PathBuf,
    #[serde(default)]
    directory: Option<PathBuf>,
    #[serde(default)]
    arguments: Vec<String>,
    #[serde(default)]
    command: Option<String>,
    #[serde(default)]
    output: Option<PathBuf>,
}

pub fn resolve_tu_spec(root: &Path, file_hint: Option<&Path>) -> Result<TUSpec, String> {
    if let Some(spec) = resolve_from_compile_commands(root, file_hint)? {
        return Ok(spec);
    }
    if let Some(spec) = resolve_from_compile_flags(root, file_hint)? {
        return Ok(spec);
    }
    if let Some(spec) = resolve_from_fixture_metadata(root)? {
        return Ok(spec);
    }
    synthesize_tu_spec(root, file_hint)
}

pub fn resolve_tu_spec_for_codeql_database(
    source_root: &Path,
    db_root: &Path,
    file_hint: Option<&Path>,
) -> Result<TUSpec, String> {
    if let Some(spec) = resolve_from_codeql_extraction_commands(source_root, db_root, file_hint)? {
        return Ok(spec);
    }
    resolve_tu_spec(source_root, file_hint)
}

fn resolve_from_compile_commands(
    root: &Path,
    file_hint: Option<&Path>,
) -> Result<Option<TUSpec>, String> {
    let db_path = root.join("compile_commands.json");
    if !db_path.is_file() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&db_path)
        .map_err(|e| format!("failed to read {}: {}", db_path.display(), e))?;
    let mut entries: Vec<CompileCommandEntry> =
        serde_json::from_str(&text).map_err(|e| format!("invalid compile_commands.json: {e}"))?;
    if entries.is_empty() {
        return Ok(None);
    }
    let target_file = file_hint.map(|p| normalize_path(root, p));
    entries.sort_by(|left, right| {
        rank_compile_command(root, left, target_file.as_deref())
            .cmp(&rank_compile_command(root, right, target_file.as_deref()))
            .reverse()
    });
    let entry = entries
        .into_iter()
        .next()
        .ok_or_else(|| "compile_commands.json contained no usable entries".to_string())?;
    Ok(Some(build_tu_spec(
        root,
        entry.directory,
        entry.file,
        if entry.arguments.is_empty() {
            split_command(entry.command.as_deref().unwrap_or_default())?
        } else {
            entry.arguments
        },
        entry.command,
        entry.output,
        TUSpecSource::CompileCommands,
        format!(
            "selected compile_commands entry using deterministic ranking{}",
            target_file
                .as_ref()
                .map(|file| format!(" for {}", file.display()))
                .unwrap_or_default()
        ),
    )))
}

fn resolve_from_compile_flags(
    root: &Path,
    file_hint: Option<&Path>,
) -> Result<Option<TUSpec>, String> {
    let flags_path = root.join("compile_flags.txt");
    if !flags_path.is_file() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&flags_path)
        .map_err(|e| format!("failed to read {}: {}", flags_path.display(), e))?;
    let file = file_hint
        .map(|path| normalize_path(root, path))
        .or_else(|| discover_first_source(root))
        .ok_or_else(|| "compile_flags.txt fallback requires a source file".to_string())?;
    let mut arguments = vec!["clang++".to_string()];
    arguments.extend(
        text.lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(ToOwned::to_owned),
    );
    Ok(Some(build_tu_spec(
        root,
        root.to_path_buf(),
        file,
        arguments,
        None,
        None,
        TUSpecSource::CompileFlags,
        "selected compile_flags.txt fallback (triage-grade by default)".to_string(),
    )))
}

fn resolve_from_codeql_extraction_commands(
    source_root: &Path,
    db_root: &Path,
    file_hint: Option<&Path>,
) -> Result<Option<TUSpec>, String> {
    let db_path = db_root.join("log/extraction_commands.json");
    if !db_path.is_file() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&db_path)
        .map_err(|e| format!("failed to read {}: {}", db_path.display(), e))?;
    let mut entries: Vec<CompileCommandEntry> = serde_json::from_str(&text)
        .map_err(|e| format!("invalid extraction_commands.json: {e}"))?;
    if entries.is_empty() {
        return Ok(None);
    }
    let target_file = file_hint.map(|p| normalize_path(source_root, p));
    entries.sort_by(|left, right| {
        rank_compile_command(source_root, left, target_file.as_deref())
            .cmp(&rank_compile_command(
                source_root,
                right,
                target_file.as_deref(),
            ))
            .reverse()
    });
    let entry = entries
        .into_iter()
        .next()
        .ok_or_else(|| "extraction_commands.json contained no usable entries".to_string())?;
    let arguments = normalize_codeql_extraction_arguments(&entry.arguments);
    if arguments.is_empty() {
        return Ok(None);
    }
    Ok(Some(build_tu_spec(
        source_root,
        entry.directory,
        entry.file,
        arguments,
        entry.command,
        entry.output,
        TUSpecSource::CodeQlExtractionCommands,
        format!(
            "selected CodeQL extraction_commands entry using deterministic ranking{}",
            target_file
                .as_ref()
                .map(|file| format!(" for {}", file.display()))
                .unwrap_or_default()
        ),
    )))
}

fn resolve_from_fixture_metadata(root: &Path) -> Result<Option<TUSpec>, String> {
    let fixture_path = root.join("fat-tuspec.json");
    if !fixture_path.is_file() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&fixture_path)
        .map_err(|e| format!("failed to read {}: {}", fixture_path.display(), e))?;
    let spec: FixtureTuSpec =
        serde_json::from_str(&text).map_err(|e| format!("invalid fat-tuspec.json: {e}"))?;
    Ok(Some(build_tu_spec(
        root,
        spec.directory.unwrap_or_else(|| root.to_path_buf()),
        spec.file,
        spec.arguments,
        spec.command,
        spec.output,
        TUSpecSource::FixtureMetadata,
        "selected fixture metadata fallback".to_string(),
    )))
}

fn synthesize_tu_spec(root: &Path, file_hint: Option<&Path>) -> Result<TUSpec, String> {
    let file = file_hint
        .map(|path| normalize_path(root, path))
        .or_else(|| discover_first_source(root))
        .ok_or_else(|| format!("could not discover a source file under {}", root.display()))?;
    let language = if file.extension() == Some(OsStr::new("mm")) {
        "objective-c++"
    } else if file.extension() == Some(OsStr::new("m")) {
        "objective-c"
    } else {
        "c++"
    };
    let arguments = vec![
        "clang++".to_string(),
        "-x".to_string(),
        language.to_string(),
        "-std=c++17".to_string(),
    ];
    Ok(build_tu_spec(
        root,
        root.to_path_buf(),
        file,
        arguments,
        None,
        None,
        TUSpecSource::Synthesized,
        "selected synthesized TU fallback".to_string(),
    ))
}

fn build_tu_spec(
    root: &Path,
    directory: PathBuf,
    file: PathBuf,
    arguments: Vec<String>,
    command: Option<String>,
    output: Option<PathBuf>,
    source: TUSpecSource,
    selection_reason: String,
) -> TUSpec {
    let file = normalize_path(root, &file);
    let directory = normalize_path(root, &directory);
    let output = output.map(|path| normalize_path(root, &path));
    let hash = hash_tu_spec(&directory, &file, &arguments, output.as_ref(), &source);
    TUSpec {
        file,
        directory,
        arguments,
        command,
        output,
        source,
        selection_reason,
        hash,
    }
}

fn normalize_codeql_extraction_arguments(arguments: &[String]) -> Vec<String> {
    if arguments.len() >= 2 && arguments[0] == "--mimic" {
        let mut normalized = vec![arguments[1].clone()];
        normalized.extend(arguments.iter().skip(2).cloned());
        return normalized;
    }
    arguments.to_vec()
}

fn hash_tu_spec(
    directory: &Path,
    file: &Path,
    arguments: &[String],
    output: Option<&PathBuf>,
    source: &TUSpecSource,
) -> String {
    let payload = serde_json::json!({
        "directory": directory,
        "file": file,
        "arguments": arguments,
        "output": output,
        "source": source,
    });
    let mut hasher = Sha256::new();
    hasher.update(serde_json::to_vec(&payload).unwrap_or_default());
    format!("{:x}", hasher.finalize())
}

fn normalize_path(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

fn rank_compile_command(
    root: &Path,
    entry: &CompileCommandEntry,
    target_file: Option<&Path>,
) -> (u8, u8, u8, u8, String) {
    let normalized_file = normalize_path(root, &entry.file);
    let exact_file = target_file.is_some_and(|file| file == normalized_file);
    let exact_output = target_file.is_some_and(|file| {
        entry
            .output
            .as_ref()
            .map(|output| normalize_path(root, output) == file)
            .unwrap_or(false)
    });
    let has_target = entry
        .arguments
        .iter()
        .zip(entry.arguments.iter().skip(1))
        .any(|(left, _)| left == "-target");
    let has_sdk = entry
        .arguments
        .iter()
        .zip(entry.arguments.iter().skip(1))
        .any(|(left, _)| left == "-isysroot");
    let preferred_dir = entry.directory.to_string_lossy().contains("out")
        || entry.directory.to_string_lossy().contains("build");
    (
        exact_output as u8,
        exact_file as u8,
        (has_target || has_sdk || preferred_dir) as u8,
        preferred_dir as u8,
        normalized_file.display().to_string(),
    )
}

fn split_command(command: &str) -> Result<Vec<String>, String> {
    shell_words::split(command).map_err(|e| format!("failed to split command string: {e}"))
}

fn discover_first_source(root: &Path) -> Option<PathBuf> {
    discover_sources(root).into_iter().next()
}

/// Preference rank for a candidate translation-unit source (lower = better):
/// an implementation file is a far better TU than a bare header.
fn source_rank(path: &Path) -> u8 {
    match path.extension().and_then(|ext| ext.to_str()) {
        Some("cpp" | "cc" | "cxx" | "mm" | "m" | "c") => 0,
        Some("rs") => 1,
        _ => 2, // headers (.h/.hpp)
    }
}

/// Collect candidate TU sources under `root`, deterministically ordered
/// (implementation files first, then by path). Deterministic order matters:
/// WalkDir yields OS-native directory order, which otherwise makes the chosen
/// source — and thus discovery output — vary across platforms.
fn discover_sources(root: &Path) -> Vec<PathBuf> {
    let mut sources: Vec<PathBuf> = walkdir::WalkDir::new(root)
        .follow_links(false)
        .into_iter()
        .filter_map(Result::ok)
        .filter(|entry| entry.path().is_file())
        .filter_map(|entry| {
            let path = entry.path();
            let ext = path.extension().and_then(|ext| ext.to_str())?;
            matches!(
                ext,
                "c" | "cc" | "cpp" | "cxx" | "m" | "mm" | "h" | "hpp" | "rs"
            )
            .then(|| path.to_path_buf())
        })
        .collect();
    sources.sort_by(|left, right| {
        source_rank(left)
            .cmp(&source_rank(right))
            .then(left.cmp(right))
    });
    sources
}

#[cfg(test)]
mod discovery_tests {
    use super::{discover_first_source, discover_sources};

    #[test]
    fn prefers_implementation_over_header_and_is_deterministic() {
        let dir = tempfile::tempdir().unwrap();
        let root = dir.path();
        std::fs::create_dir_all(root.join("inc")).unwrap();
        std::fs::write(root.join("inc/Widget.h"), "// header").unwrap();
        std::fs::write(root.join("src_a.cpp"), "// impl a").unwrap();
        std::fs::write(root.join("src_b.cpp"), "// impl b").unwrap();

        let sources = discover_sources(root);
        // Implementation files come before the header.
        assert!(sources[0].extension().unwrap() == "cpp");
        assert!(sources.last().unwrap().extension().unwrap() == "h");
        // Deterministic: first impl is the lexicographically-smallest path.
        assert!(discover_first_source(root).unwrap().ends_with("src_a.cpp"));
        // Stable across repeated calls.
        assert_eq!(discover_sources(root), sources);
    }

    #[test]
    fn header_only_tree_still_yields_a_source() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("only.h"), "// header").unwrap();
        assert!(discover_first_source(dir.path())
            .unwrap()
            .ends_with("only.h"));
    }
}
