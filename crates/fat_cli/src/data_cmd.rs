use std::collections::BTreeSet;
use std::error::Error;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

use clap::Subcommand;
use fat_core::data_dir::{default_user_data_root, DataResolver, FAT_DATA_DIR_ENV};
use fat_core::data_manifest::{DataManifest, DATA_MANIFEST_FILE};
use fat_core::zip_preflight::{preflight_zip_file, ZipPreflightLimits};
use serde::{Deserialize, Serialize};

type DynResult<T> = Result<T, Box<dyn Error>>;

const MAX_DATA_ARCHIVE_ENTRIES: usize = 1_024;
const MAX_DATA_ARCHIVE_EXPANDED_BYTES: u64 = 32 * 1024 * 1024;
const MAX_DATA_MANIFEST_BYTES: u64 = 1024 * 1024;
const MAX_DATA_ARCHIVE_FILE_BYTES: u64 = 128 * 1024 * 1024;
const MAX_DATA_ARCHIVE_CENTRAL_DIRECTORY_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Subcommand)]
pub(crate) enum DataCommand {
    /// Report the active FAT runtime data version.
    Status {
        #[arg(long)]
        data_dir: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Install and activate a verified local FAT data directory or ZIP archive.
    Install {
        #[arg(long)]
        archive: PathBuf,
        #[arg(long)]
        data_dir: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Verify every file in the active FAT data version.
    Verify {
        #[arg(long)]
        data_dir: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// List locally installed FAT data versions.
    List {
        #[arg(long)]
        data_dir: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ActiveData {
    data_version: String,
    relative_path: String,
}

#[derive(Debug, Serialize)]
struct DataStatus<'a> {
    status: &'a str,
    data_root: String,
    data_version: Option<String>,
    active_path: Option<String>,
    origin: Option<String>,
}

#[derive(Debug, Serialize)]
struct InstallResult {
    status: &'static str,
    data_root: String,
    data_version: String,
    verified_files: usize,
    missing_optional_files: usize,
}

#[derive(Debug, Serialize)]
struct VersionList {
    data_root: String,
    versions: Vec<String>,
}

pub(crate) fn run(command: DataCommand) -> DynResult<()> {
    match command {
        DataCommand::Status { data_dir, json } => status(data_dir, json),
        DataCommand::Install {
            archive,
            data_dir,
            json,
        } => install(&archive, &managed_root(data_dir)?, json),
        DataCommand::Verify { data_dir, json } => verify(data_dir, json),
        DataCommand::List { data_dir, json } => list(&managed_root(data_dir)?, json),
    }
}

fn managed_root(explicit: Option<PathBuf>) -> DynResult<PathBuf> {
    if let Some(path) = explicit {
        return Ok(path);
    }
    if let Some(path) = std::env::var_os(FAT_DATA_DIR_ENV) {
        return Ok(PathBuf::from(path));
    }
    default_user_data_root().ok_or_else(|| {
        format!("cannot determine the FAT user data directory; set {FAT_DATA_DIR_ENV}").into()
    })
}

fn status(explicit_root: Option<PathBuf>, json: bool) -> DynResult<()> {
    let resolver = active_data_resolver(explicit_root);
    let result = match resolver.resolve_required(DATA_MANIFEST_FILE) {
        Ok(resolved) => {
            let manifest = DataManifest::load(&resolved.root);
            let ready = manifest.as_ref().is_ok_and(|manifest| {
                manifest
                    .verify_tree(&resolved.root, env!("CARGO_PKG_VERSION"))
                    .is_ok()
            });
            let data_root = resolver
                .roots()
                .iter()
                .find(|root| {
                    root.origin == resolved.origin && resolved.root.starts_with(&root.path)
                })
                .map(|root| root.path.display().to_string())
                .unwrap_or_else(|| resolved.root.display().to_string());
            DataStatus {
                status: if ready { "ready" } else { "broken" },
                data_root,
                data_version: manifest.ok().map(|manifest| manifest.data_version),
                active_path: Some(resolved.root.display().to_string()),
                origin: Some(resolved.origin.to_string()),
            }
        }
        Err(_) => unresolved_status(&resolver)?,
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else if result.status == "ready" {
        println!(
            "FAT data: {} ({})\nRoot: {}\nOrigin: {}",
            result.status,
            result.data_version.as_deref().unwrap_or("unknown version"),
            result.data_root,
            result.origin.as_deref().unwrap_or("unknown")
        );
    } else if result.status == "broken" {
        let version = result
            .data_version
            .as_deref()
            .map(|version| format!(" ({version})"))
            .unwrap_or_default();
        println!(
            "FAT data: broken{version}\nRoot: {}\nOrigin: {}",
            result.data_root,
            result.origin.as_deref().unwrap_or("unknown")
        );
    } else {
        println!(
            "FAT data: not installed\nRoot: {}\nOrigin: {}\nRun `fat data install --archive <path>`.",
            result.data_root,
            result.origin.as_deref().unwrap_or("unknown")
        );
    }
    Ok(())
}

fn active_data_resolver(explicit_root: Option<PathBuf>) -> DataResolver {
    if explicit_root.is_some() {
        DataResolver::from_paths(explicit_root, None, None, None, None)
    } else if let Some(environment_root) = std::env::var_os(FAT_DATA_DIR_ENV).map(PathBuf::from) {
        DataResolver::from_paths(None, Some(environment_root), None, None, None)
    } else {
        DataResolver::for_current_process(None)
    }
}

fn unresolved_status(resolver: &DataResolver) -> DynResult<DataStatus<'static>> {
    for root in resolver.roots() {
        match inspect_active(&root.path) {
            ActiveRecordStatus::Valid(active) => {
                return Ok(DataStatus {
                    status: "broken",
                    data_root: root.path.display().to_string(),
                    data_version: Some(active.data_version),
                    active_path: Some(root.path.join(active.relative_path).display().to_string()),
                    origin: Some(root.origin.to_string()),
                })
            }
            ActiveRecordStatus::Invalid => {
                return Ok(DataStatus {
                    status: "broken",
                    data_root: root.path.display().to_string(),
                    data_version: None,
                    active_path: None,
                    origin: Some(root.origin.to_string()),
                })
            }
            ActiveRecordStatus::Missing => {}
        }
    }
    let root = resolver
        .roots()
        .first()
        .map(|root| root.path.clone())
        .or_else(default_user_data_root)
        .ok_or_else(|| {
            format!("cannot determine the FAT data directory; set {FAT_DATA_DIR_ENV}")
        })?;
    Ok(DataStatus {
        status: "missing",
        data_root: root.display().to_string(),
        data_version: None,
        active_path: None,
        origin: resolver.roots().first().map(|root| root.origin.to_string()),
    })
}

enum ActiveRecordStatus {
    Missing,
    Valid(ActiveData),
    Invalid,
}

fn inspect_active(root: &Path) -> ActiveRecordStatus {
    match fs::read_to_string(root.join("active.json")) {
        Ok(text) => serde_json::from_str(&text)
            .map(ActiveRecordStatus::Valid)
            .unwrap_or(ActiveRecordStatus::Invalid),
        Err(error) if error.kind() == io::ErrorKind::NotFound => ActiveRecordStatus::Missing,
        Err(_) => ActiveRecordStatus::Invalid,
    }
}

fn install(archive: &Path, root: &Path, json: bool) -> DynResult<()> {
    let extracted;
    let source = if archive.is_dir() {
        archive
    } else if archive.extension().and_then(|value| value.to_str()) == Some("zip") {
        extracted = tempfile::tempdir()?;
        extract_zip(archive, extracted.path())?;
        extracted.path()
    } else {
        return Err(format!(
            "unsupported FAT data archive {}; provide a directory or .zip file",
            archive.display()
        )
        .into());
    };

    reject_symlink(source.join(DATA_MANIFEST_FILE).as_path())?;
    let manifest = DataManifest::load(source)?;
    let source_report = manifest.verify_tree(source, env!("CARGO_PKG_VERSION"))?;

    let versions = root.join("versions");
    fs::create_dir_all(&versions)?;
    let final_root = versions.join(&manifest.data_version);
    if final_root.exists() {
        return Err(format!(
            "FAT data version {} is already installed at {}",
            manifest.data_version,
            final_root.display()
        )
        .into());
    }

    let staging = tempfile::Builder::new()
        .prefix(".fat-data-install-")
        .tempdir_in(&versions)?;
    fs::copy(
        source.join(DATA_MANIFEST_FILE),
        staging.path().join(DATA_MANIFEST_FILE),
    )?;
    for entry in &manifest.files {
        let source_path = source.join(&entry.path);
        if !source_path.exists() && !entry.required {
            continue;
        }
        let destination = staging.path().join(&entry.path);
        fs::create_dir_all(destination.parent().ok_or("invalid FAT data entry path")?)?;
        fs::copy(source_path, destination)?;
    }
    let staged_report = manifest.verify_tree(staging.path(), env!("CARGO_PKG_VERSION"))?;
    fs::rename(staging.path(), &final_root)?;

    let active = ActiveData {
        data_version: manifest.data_version.clone(),
        relative_path: format!("versions/{}", manifest.data_version),
    };
    write_active(root, &active)?;

    let result = InstallResult {
        status: "installed",
        data_root: root.display().to_string(),
        data_version: manifest.data_version,
        verified_files: staged_report.verified_files,
        missing_optional_files: staged_report.missing_optional_files,
    };
    debug_assert_eq!(
        source_report.verified_files, staged_report.verified_files,
        "staged data verification changed the source file count"
    );
    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!(
            "Installed FAT data {} ({} verified files) at {}",
            result.data_version, result.verified_files, result.data_root
        );
    }
    Ok(())
}

fn verify(explicit_root: Option<PathBuf>, json: bool) -> DynResult<()> {
    let resolver = active_data_resolver(explicit_root);
    let resolved = resolver.resolve_required(DATA_MANIFEST_FILE)?;
    let manifest = DataManifest::load(&resolved.root)?;
    let report = manifest.verify_tree(&resolved.root, env!("CARGO_PKG_VERSION"))?;
    let data_root = resolver
        .roots()
        .iter()
        .find(|root| root.origin == resolved.origin && resolved.root.starts_with(&root.path))
        .map(|root| root.path.display().to_string())
        .unwrap_or_else(|| resolved.root.display().to_string());
    let result = InstallResult {
        status: "verified",
        data_root,
        data_version: manifest.data_version,
        verified_files: report.verified_files,
        missing_optional_files: report.missing_optional_files,
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!(
            "Verified FAT data {} ({} files)",
            result.data_version, result.verified_files
        );
    }
    Ok(())
}

fn list(root: &Path, json: bool) -> DynResult<()> {
    let versions_root = root.join("versions");
    let mut versions = Vec::new();
    if versions_root.is_dir() {
        for entry in fs::read_dir(&versions_root)? {
            let entry = entry?;
            if entry.file_type()?.is_dir() {
                let name = entry.file_name().to_string_lossy().into_owned();
                if !name.starts_with(".fat-data-install-") {
                    versions.push(name);
                }
            }
        }
    }
    versions.sort();
    let result = VersionList {
        data_root: root.display().to_string(),
        versions,
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else if result.versions.is_empty() {
        println!("No FAT data versions are installed at {}", result.data_root);
    } else {
        println!("Installed FAT data versions:");
        for version in &result.versions {
            println!("  {version}");
        }
    }
    Ok(())
}

fn extract_zip(archive: &Path, destination: &Path) -> DynResult<()> {
    let mut file = File::open(archive)?;
    preflight_zip_file(
        &mut file,
        ZipPreflightLimits {
            max_file_bytes: MAX_DATA_ARCHIVE_FILE_BYTES,
            max_entries: MAX_DATA_ARCHIVE_ENTRIES as u64,
            max_central_directory_bytes: MAX_DATA_ARCHIVE_CENTRAL_DIRECTORY_BYTES,
        },
    )?;
    let mut zip = zip::ZipArchive::new(file)?;
    if zip.len() > MAX_DATA_ARCHIVE_ENTRIES {
        return Err(format!(
            "FAT data archive has too many entries: {} exceeds {}",
            zip.len(),
            MAX_DATA_ARCHIVE_ENTRIES
        )
        .into());
    }

    let mut seen = BTreeSet::new();
    let mut expanded_bytes = 0_u64;
    for index in 0..zip.len() {
        let entry = zip.by_index(index)?;
        let relative = entry
            .enclosed_name()
            .ok_or_else(|| format!("unsafe archive path: {}", entry.name()))?
            .to_path_buf();
        if !seen.insert(relative.clone()) {
            return Err(format!("duplicate archive path: {}", entry.name()).into());
        }
        if entry
            .unix_mode()
            .is_some_and(|mode| mode & 0o170000 == 0o120000)
        {
            return Err(format!("unsafe archive symlink: {}", entry.name()).into());
        }
        if !entry.is_dir() {
            expanded_bytes = expanded_bytes
                .checked_add(entry.size())
                .ok_or("FAT data archive expanded byte count overflowed")?;
            if expanded_bytes > MAX_DATA_ARCHIVE_EXPANDED_BYTES {
                return Err(format!(
                    "FAT data archive exceeds expanded byte limit of {MAX_DATA_ARCHIVE_EXPANDED_BYTES} bytes"
                )
                .into());
            }
        }
    }

    let manifest_bytes = {
        let mut entry = zip
            .by_name(DATA_MANIFEST_FILE)
            .map_err(|_| "FAT data archive is missing manifest.json")?;
        if entry.size() > MAX_DATA_MANIFEST_BYTES {
            return Err("FAT data archive manifest exceeds size limit".into());
        }
        let mut bytes = Vec::with_capacity(entry.size() as usize);
        entry
            .by_ref()
            .take(MAX_DATA_MANIFEST_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.len() as u64 > MAX_DATA_MANIFEST_BYTES {
            return Err("FAT data archive manifest exceeds size limit".into());
        }
        bytes
    };
    let manifest = DataManifest::from_json(std::str::from_utf8(&manifest_bytes)?)?;
    let mut allowed_files = BTreeSet::from([PathBuf::from(DATA_MANIFEST_FILE)]);
    for item in &manifest.files {
        let relative = PathBuf::from(&item.path);
        if !allowed_files.insert(relative) {
            return Err(format!("duplicate FAT data manifest path: {}", item.path).into());
        }
    }

    for path in &seen {
        let declared = allowed_files.contains(path)
            || allowed_files
                .iter()
                .any(|allowed| allowed.starts_with(path));
        if !declared {
            return Err(format!("undeclared archive payload: {}", path.display()).into());
        }
    }

    let mut streamed_bytes = 0_u64;
    for index in 0..zip.len() {
        let mut entry = zip.by_index(index)?;
        let relative = entry
            .enclosed_name()
            .ok_or("unsafe archive path")?
            .to_path_buf();
        if entry.is_dir() {
            continue;
        }
        let output = destination.join(relative);
        fs::create_dir_all(output.parent().ok_or("invalid archive entry path")?)?;
        let mut file = File::create(output)?;
        copy_entry_with_ceiling(
            &mut entry,
            &mut file,
            &mut streamed_bytes,
            MAX_DATA_ARCHIVE_EXPANDED_BYTES,
        )?;
    }
    Ok(())
}

fn copy_entry_with_ceiling<R: Read, W: Write>(
    reader: &mut R,
    writer: &mut W,
    streamed_bytes: &mut u64,
    max_bytes: u64,
) -> DynResult<()> {
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let remaining = max_bytes.saturating_sub(*streamed_bytes);
        let read_limit = usize::try_from(remaining.saturating_add(1))
            .unwrap_or(usize::MAX)
            .min(buffer.len());
        let read = reader.read(&mut buffer[..read_limit])?;
        if read == 0 {
            return Ok(());
        }
        if read as u64 > remaining {
            return Err(format!(
                "FAT data archive exceeds expanded byte limit of {max_bytes} bytes"
            )
            .into());
        }
        writer.write_all(&buffer[..read])?;
        *streamed_bytes = streamed_bytes
            .checked_add(read as u64)
            .ok_or("FAT data archive streamed byte count overflowed")?;
    }
}

fn write_active(root: &Path, active: &ActiveData) -> DynResult<()> {
    fs::create_dir_all(root)?;
    let mut temporary = tempfile::NamedTempFile::new_in(root)?;
    serde_json::to_writer_pretty(&mut temporary, active)?;
    temporary.write_all(b"\n")?;
    temporary.flush()?;
    temporary
        .persist(root.join("active.json"))
        .map_err(|error| error.error)?;
    Ok(())
}

fn reject_symlink(path: &Path) -> DynResult<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() {
        return Err(format!("unsafe FAT data symlink: {}", path.display()).into());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn streamed_archive_limit_is_checked_before_overflow_bytes_are_written() {
        let mut input = io::Cursor::new(vec![b'x'; 9]);
        let mut output = Vec::new();
        let mut streamed = 0;

        let error = copy_entry_with_ceiling(&mut input, &mut output, &mut streamed, 8)
            .expect_err("ninth byte must exceed ceiling");

        assert!(error.to_string().contains("expanded byte limit"));
        assert!(output.len() <= 8, "must never write limit+1 bytes");
        assert_eq!(streamed, output.len() as u64);
    }
}
