use std::error::Error;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use clap::Subcommand;
use serde::Serialize;
use sha2::{Digest, Sha256};

use fat_core::rehosting_pack::{
    parse_rehosting_pack_yaml, validate_rehosting_pack, RehostingPack,
    RehostingPackValidationReport,
};
use fat_core::rehosting_pack_match::{score_pack, PackMatch, PackMatchInput};

use crate::style::Palette;

type DynResult<T> = Result<T, Box<dyn Error>>;

/// Environment variable holding `:`-separated pack search directories.
const PACK_PATH_ENV: &str = "FAT_REHOSTING_PACKS";

#[derive(Debug, Clone, Subcommand)]
pub enum RehostCommand {
    #[command(about = "Inspect and validate rehosting pack profiles.")]
    Profiles {
        #[command(subcommand)]
        command: RehostProfilesCommand,
    },
    #[command(about = "Rank rehosting packs that match a project's firmware.")]
    Match {
        /// Project directory (positional).
        project: Option<PathBuf>,
        /// Project directory (alias for the positional argument).
        #[arg(long = "project")]
        project_flag: Option<PathBuf>,
        /// Directory to search for packs (repeatable). Packs are found only in
        /// the directories given here and in `FAT_REHOSTING_PACKS`; FAT ships
        /// no packs of its own.
        #[arg(long = "packs-dir")]
        packs_dirs: Vec<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Subcommand)]
pub enum RehostProfilesCommand {
    #[command(about = "Validate a local rehosting pack YAML file.")]
    Validate {
        /// Pack YAML path (positional).
        path: Option<PathBuf>,
        /// Pack YAML path (alias for the positional argument).
        #[arg(long = "file")]
        file: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    #[command(about = "Show a local rehosting pack with validation status.")]
    Show {
        /// Pack YAML path (positional).
        path: Option<PathBuf>,
        /// Pack YAML path (alias for the positional argument).
        #[arg(long = "file")]
        file: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}

fn resolve_pack_path(path: Option<PathBuf>, file: Option<PathBuf>) -> DynResult<PathBuf> {
    path.or(file)
        .ok_or_else(|| "a rehosting pack path is required (positionally or via --file)".into())
}

#[derive(Debug, Serialize)]
struct RehostingPackShowReport {
    pack: RehostingPack,
    validation: RehostingPackValidationReport,
}

pub fn run(command: RehostCommand) -> DynResult<()> {
    match command {
        RehostCommand::Match {
            project,
            project_flag,
            packs_dirs,
            json,
        } => match_packs(
            &crate::resolve_project_arg(project, project_flag)?,
            &packs_dirs,
            json,
        ),
        RehostCommand::Profiles { command } => match command {
            RehostProfilesCommand::Validate { path, file, json } => {
                validate_profile(&resolve_pack_path(path, file)?, json)
            }
            RehostProfilesCommand::Show { path, file, json } => {
                show_profile(&resolve_pack_path(path, file)?, json)
            }
        },
    }
}

fn validate_profile(path: &Path, json: bool) -> DynResult<()> {
    let pack = load_pack(path)?;
    let report = validate_rehosting_pack(&pack);

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if report.valid {
        println!("valid rehosting pack: {} ({})", pack.id, path.display());
        if !report.warnings.is_empty() {
            println!("warnings:");
            for warning in &report.warnings {
                println!("  [{}] {}", warning.code, warning.message);
            }
        }
    }

    if report.valid {
        Ok(())
    } else {
        Err(render_validation_errors(&pack.id, &report).into())
    }
}

fn show_profile(path: &Path, json: bool) -> DynResult<()> {
    let pack = load_pack(path)?;
    let validation = validate_rehosting_pack(&pack);

    if json {
        let report = RehostingPackShowReport { pack, validation };
        println!("{}", serde_json::to_string_pretty(&report)?);
        return Ok(());
    }

    println!("rehosting pack: {}", pack.id);
    println!("kind: {}", pack.kind);
    println!("version: {}", pack.version);
    println!(
        "architecture: {}",
        pack.match_rules
            .architecture
            .as_deref()
            .unwrap_or("unspecified")
    );
    println!("signals: {}", pack.match_rules.signals.len());
    println!("paths: {}", pack.match_rules.paths.len());
    println!("validators: {}", pack.validators.len());
    println!(
        "validation: {}",
        if validation.valid { "valid" } else { "invalid" }
    );
    for error in &validation.errors {
        println!("  error [{}] {}", error.code, error.message);
    }
    for warning in &validation.warnings {
        println!("  warning [{}] {}", warning.code, warning.message);
    }
    Ok(())
}

pub(crate) fn load_pack(path: &Path) -> DynResult<RehostingPack> {
    let yaml = fs::read_to_string(path)
        .map_err(|err| format!("failed to read rehosting pack '{}': {err}", path.display()))?;
    parse_rehosting_pack_yaml(&yaml)
        .map_err(|err| format!("invalid rehosting pack '{}': {err}", path.display()).into())
}

fn render_validation_errors(pack_id: &str, report: &RehostingPackValidationReport) -> String {
    let mut lines = vec![format!("invalid rehosting pack: {pack_id}")];
    for error in &report.errors {
        lines.push(format!("  [{}] {}", error.code, error.message));
    }
    lines.join("\n")
}

/// A discovered pack together with where it was loaded from.
#[derive(Debug)]
pub(crate) struct DiscoveredPack {
    pub(crate) path: PathBuf,
    pub(crate) pack: RehostingPack,
}

#[derive(Debug)]
pub(crate) struct PackDiscoveryDiagnostic {
    pub(crate) path: PathBuf,
    pub(crate) code: &'static str,
    pub(crate) message: String,
}

#[derive(Debug, Default)]
pub(crate) struct PackDiscovery {
    pub(crate) packs: Vec<DiscoveredPack>,
    pub(crate) diagnostics: Vec<PackDiscoveryDiagnostic>,
}

/// Search roots for packs, in precedence order: `--packs-dir` directories in
/// the order given, then `FAT_REHOSTING_PACKS`.
///
/// There is no implicit root. FAT distributes no target packs, so with no
/// source selected nothing is discovered and no pack can be applied. A pack
/// left behind in a data directory by an older install is therefore inert
/// rather than silently active.
pub(crate) fn pack_search_roots(extra: &[PathBuf]) -> Vec<PathBuf> {
    let mut roots: Vec<PathBuf> = extra.to_vec();
    if let Some(env_paths) = std::env::var_os(PACK_PATH_ENV) {
        roots.extend(std::env::split_paths(&env_paths));
    }
    roots
}

/// Discover valid rehosting packs under the given roots. Invalid/unparseable
/// YAML files are skipped rather than aborting discovery.
pub(crate) fn discover_packs(roots: &[PathBuf]) -> PackDiscovery {
    let mut discovery = PackDiscovery::default();
    let mut seen = std::collections::BTreeSet::new();
    for root in roots {
        for entry in walkdir::WalkDir::new(root) {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    discovery.diagnostics.push(PackDiscoveryDiagnostic {
                        path: error
                            .path()
                            .map(Path::to_path_buf)
                            .unwrap_or_else(|| root.clone()),
                        code: "walk-error",
                        message: error.to_string(),
                    });
                    continue;
                }
            };
            if !entry.file_type().is_file() {
                continue;
            }
            let path = entry.path();
            let is_yaml = matches!(
                path.extension().and_then(|ext| ext.to_str()),
                Some("yaml") | Some("yml")
            );
            if !is_yaml {
                continue;
            }
            let canonical = match std::fs::canonicalize(path) {
                Ok(path) => path,
                Err(error) => {
                    discovery.diagnostics.push(PackDiscoveryDiagnostic {
                        path: path.to_path_buf(),
                        code: "canonicalize-error",
                        message: error.to_string(),
                    });
                    continue;
                }
            };
            if !seen.insert(canonical.clone()) {
                continue;
            }
            let text = match std::fs::read_to_string(path) {
                Ok(text) => text,
                Err(error) => {
                    discovery.diagnostics.push(PackDiscoveryDiagnostic {
                        path: path.to_path_buf(),
                        code: "read-error",
                        message: error.to_string(),
                    });
                    continue;
                }
            };
            let pack = match parse_rehosting_pack_yaml(&text) {
                Ok(pack) => pack,
                Err(error) => {
                    discovery.diagnostics.push(PackDiscoveryDiagnostic {
                        path: path.to_path_buf(),
                        code: "parse-error",
                        message: error,
                    });
                    continue;
                }
            };
            let validation = validate_rehosting_pack(&pack);
            if !validation.valid {
                discovery.diagnostics.push(PackDiscoveryDiagnostic {
                    path: path.to_path_buf(),
                    code: "validation-error",
                    message: render_validation_errors(&pack.id, &validation),
                });
                continue;
            }
            discovery.packs.push(DiscoveredPack {
                path: path.to_path_buf(),
                pack,
            });
        }
    }
    discovery
}

#[derive(Debug, Serialize)]
struct PackMatchRow {
    id: String,
    path: String,
    score: f32,
    is_match: bool,
    arch_gate_passed: bool,
    sha_exact: bool,
    matched_signals: Vec<String>,
    missing_signals: Vec<String>,
    matched_paths: Vec<String>,
    missing_paths: Vec<String>,
    reasons: Vec<String>,
}

/// Auto-select the best matching pack for a target's signals. Returns the
/// highest-scoring pack that actually matches, or `None` if nothing matches.
pub(crate) fn auto_select_pack(
    project_dir: &Path,
    signals: &[String],
    extra_dirs: &[PathBuf],
) -> Option<(RehostingPack, PackMatch)> {
    let input = build_match_input(project_dir, signals.to_vec());
    let roots = pack_search_roots(extra_dirs);
    discover_packs(&roots)
        .packs
        .into_iter()
        .map(|discovered| {
            let result = score_pack(&discovered.pack, &input);
            (discovered.pack, result)
        })
        .filter(|(_, result)| result.is_match())
        .max_by(|left, right| {
            left.1
                .score
                .partial_cmp(&right.1.score)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| right.0.id.cmp(&left.0.id))
        })
}

fn match_packs(project_dir: &Path, extra_dirs: &[PathBuf], json: bool) -> DynResult<()> {
    let signals = crate::load_project_signals(project_dir).map_err(|err| {
        format!(
            "failed to load analysis signals for {} (run `fat analyze` first): {err}",
            project_dir.display()
        )
    })?;
    let input = build_match_input(project_dir, signals);

    let roots = pack_search_roots(extra_dirs);
    let discovery = discover_packs(&roots);
    emit_discovery_diagnostics(&discovery.diagnostics);
    let mut scored: Vec<(DiscoveredPack, PackMatch)> = discovery
        .packs
        .into_iter()
        .map(|discovered| {
            let result = score_pack(&discovered.pack, &input);
            (discovered, result)
        })
        .collect();
    // Best matches first; stable by id for ties.
    scored.sort_by(|left, right| {
        right
            .1
            .score
            .partial_cmp(&left.1.score)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| left.0.pack.id.cmp(&right.0.pack.id))
    });

    if json {
        let rows: Vec<PackMatchRow> = scored
            .iter()
            .map(|(discovered, result)| PackMatchRow {
                id: discovered.pack.id.clone(),
                path: discovered.path.display().to_string(),
                score: result.score,
                is_match: result.is_match(),
                arch_gate_passed: result.arch_gate_passed,
                sha_exact: result.sha_exact,
                matched_signals: result.matched_signals.clone(),
                missing_signals: result.missing_signals.clone(),
                matched_paths: result.matched_paths.clone(),
                missing_paths: result.missing_paths.clone(),
                reasons: result.reasons.clone(),
            })
            .collect();
        println!("{}", serde_json::to_string_pretty(&rows)?);
        return Ok(());
    }

    let palette = Palette::stdout();
    println!(
        "{}",
        palette.heading(format!(
            "Rehosting pack matches for {}",
            project_dir.display()
        ))
    );
    if scored.is_empty() {
        println!(
            "{} {}",
            palette.bullet("-"),
            palette.muted("no rehosting packs found on the search path")
        );
        return Ok(());
    }
    for (discovered, result) in &scored {
        let verdict = if result.is_match() {
            palette.good(format!("match  score={:.2}", result.score))
        } else {
            palette.muted(format!("no match  score={:.2}", result.score))
        };
        println!(
            "{} {}  {}",
            palette.bullet("-"),
            palette.info(&discovered.pack.id),
            verdict
        );
        for reason in &result.reasons {
            println!("    {}", palette.muted(reason));
        }
    }
    Ok(())
}

/// Resolve a `--pack` argument (a file path or a pack id) to a pack for
/// emulation. Returns `None` when no pack was requested.
pub(crate) fn resolve_pack_for_emulate(
    pack_arg: Option<&str>,
    extra_dirs: &[PathBuf],
) -> DynResult<Option<RehostingPack>> {
    let Some(arg) = pack_arg else {
        return Ok(None);
    };
    let path = Path::new(arg);
    if path.is_file() {
        let pack = load_pack(path)?;
        let validation = validate_rehosting_pack(&pack);
        if !validation.valid {
            return Err(render_validation_errors(&pack.id, &validation).into());
        }
        return Ok(Some(pack));
    }
    let roots = pack_search_roots(extra_dirs);
    let discovery = discover_packs(&roots);
    match discovery
        .packs
        .into_iter()
        .find(|discovered| discovered.pack.id == arg)
    {
        Some(discovered) => Ok(Some(discovered.pack)),
        None => {
            let mut message = format!(
                "no valid rehosting pack found matching '{arg}' (tried it as a file path and as a pack id)"
            );
            for diagnostic in discovery.diagnostics {
                message.push_str(&format!(
                    "\n  [{}] {}: {}",
                    diagnostic.code,
                    diagnostic.path.display(),
                    diagnostic.message
                ));
            }
            Err(message.into())
        }
    }
}

fn emit_discovery_diagnostics(diagnostics: &[PackDiscoveryDiagnostic]) {
    for diagnostic in diagnostics {
        eprintln!(
            "invalid rehosting pack [{}] {}: {}",
            diagnostic.code,
            diagnostic.path.display(),
            diagnostic.message
        );
    }
}

fn build_match_input(project_dir: &Path, signals: Vec<String>) -> PackMatchInput {
    PackMatchInput::from_signals(signals)
        .with_firmware_sha256(project_firmware_sha256(project_dir))
        .with_target_root(project_target_root(project_dir))
}

fn project_firmware_sha256(project_dir: &Path) -> Option<String> {
    let input_dir = project_dir.join("input");
    let mut files = fs::read_dir(input_dir)
        .ok()?
        .filter_map(Result::ok)
        .filter_map(|entry| entry.file_type().ok()?.is_file().then_some(entry.path()))
        .collect::<Vec<_>>();
    files.sort();
    let mut file = fs::File::open(files.first()?).ok()?;
    let mut hasher = Sha256::new();
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = file.read(&mut buffer).ok()?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Some(format!("{:x}", hasher.finalize()))
}

fn project_target_root(project_dir: &Path) -> Option<PathBuf> {
    let manifest_path = project_dir.join("work/extraction-manifest.json");
    if let Ok(contents) = fs::read(&manifest_path) {
        if let Ok(manifest) = serde_json::from_slice::<fat_extract::ExtractionManifest>(&contents) {
            if let Some(root) = manifest.rootfs_path {
                let root = if root.is_absolute() {
                    root
                } else {
                    project_dir.join(root)
                };
                if root.is_dir() {
                    return Some(root);
                }
            }
        }
    }
    let extracted = project_dir.join("work/extracted");
    extracted.is_dir().then_some(extracted)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn write(path: &Path, contents: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, contents).unwrap();
    }

    #[test]
    fn discover_packs_finds_valid_and_skips_invalid() {
        let dir = tempfile::tempdir().unwrap();
        write(
            &dir.path().join("acme/router.yaml"),
            "id: acme/router\nkind: rehosting-pack\nversion: \"0.1\"\nmatch:\n  signals: [fs:squashfs, init:busybox]\nvalidators:\n  - goal: boot\n    kind: manual\n",
        );
        // Wrong kind → skipped.
        write(
            &dir.path().join("acme/notpack.yaml"),
            "id: x\nkind: something-else\nversion: \"0.1\"\n",
        );
        // Unparseable → skipped.
        write(&dir.path().join("broken.yaml"), "kind: [unterminated");
        // Non-yaml → ignored.
        write(&dir.path().join("readme.txt"), "not a pack");

        let found = discover_packs(&[dir.path().to_path_buf()]);
        assert_eq!(found.packs.len(), 1);
        assert_eq!(found.packs[0].pack.id, "acme/router");
        assert_eq!(found.diagnostics.len(), 2);
    }

    #[test]
    fn auto_select_pack_picks_highest_scoring_match() {
        let dir = tempfile::tempdir().unwrap();
        // Matches architecture + both signals → score 1.0.
        write(
            &dir.path().join("acme/router.yaml"),
            "id: acme/router\nkind: rehosting-pack\nversion: \"0.1\"\nmatch:\n  architecture: armel\n  signals: [\"fs:squashfs\", \"init:busybox\"]\nvalidators:\n  - goal: boot\n    kind: manual\n",
        );
        // Wrong architecture → not a match.
        write(
            &dir.path().join("other/cam.yaml"),
            "id: other/cam\nkind: rehosting-pack\nversion: \"0.1\"\nmatch:\n  architecture: mipsel\n  signals: [\"fs:squashfs\", \"init:busybox\"]\nvalidators:\n  - goal: boot\n    kind: manual\n",
        );
        let signals = vec![
            "arch:armel".to_string(),
            "fs:squashfs".to_string(),
            "init:busybox".to_string(),
        ];
        let selected = auto_select_pack(dir.path(), &signals, &[dir.path().to_path_buf()]);
        let (pack, result) = selected.expect("a pack should match");
        assert_eq!(pack.id, "acme/router");
        assert!(result.is_match());
    }

    #[test]
    fn auto_select_pack_returns_none_when_nothing_matches() {
        let dir = tempfile::tempdir().unwrap();
        write(
            &dir.path().join("other/cam.yaml"),
            "id: other/cam\nkind: rehosting-pack\nversion: \"0.1\"\nmatch:\n  architecture: mipsel\n  signals: [fs:squashfs, init:busybox]\nvalidators:\n  - goal: boot\n    kind: manual\n",
        );
        let signals = vec!["arch:armel".to_string()];
        assert!(auto_select_pack(dir.path(), &signals, &[dir.path().to_path_buf()]).is_none());
    }

    #[test]
    fn discover_packs_dedups_same_file_from_overlapping_roots() {
        let dir = tempfile::tempdir().unwrap();
        write(
            &dir.path().join("sub/pack.yaml"),
            "id: v/d\nkind: rehosting-pack\nversion: \"0.1\"\nmatch:\n  signals: [fs:squashfs, init:busybox]\nvalidators:\n  - goal: boot\n    kind: manual\n",
        );
        let roots = vec![dir.path().to_path_buf(), dir.path().join("sub")];
        let found = discover_packs(&roots);
        assert_eq!(found.packs.len(), 1, "same file must not be counted twice");
    }

    #[test]
    fn explicit_pack_selection_rejects_a_pack_that_fails_validation() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("invalid.yaml");
        write(
            &path,
            "id: invalid/pack\nkind: rehosting-pack\nversion: \"0.1\"\nmatch:\n  architecture: armel\n",
        );

        let error = resolve_pack_for_emulate(Some(path.to_str().unwrap()), &[]).unwrap_err();

        assert!(error.to_string().contains("missing-validators"));
    }
}
