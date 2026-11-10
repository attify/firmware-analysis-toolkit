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
use sha2::{Digest, Sha256};

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
    /// Install and activate verified FAT data from a local path or the release.
    #[command(group(clap::ArgGroup::new("source").required(true).args(["archive", "release"])))]
    Install {
        /// Local FAT data directory or ZIP archive.
        #[arg(long)]
        archive: Option<PathBuf>,
        /// Download fat-data-<version>.zip and its .sha256 from the GitHub
        /// release for this executable's version.
        #[arg(long)]
        release: bool,
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
            release,
            data_dir,
            json,
        } => {
            let root = managed_root(data_dir)?;
            match (archive, release) {
                (Some(archive), false) => install(&archive, &root, json),
                (None, true) => install_release(&root, json),
                _ => Err("provide either --archive <path> or --release".into()),
            }
        }
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
            "FAT data: not installed\nRoot: {}\nOrigin: {}\nRun `fat data install --release`, or `fat data install --archive <path>` for a local bundle.",
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

/// Release asset repository, taken from the CLI manifest.
const RELEASE_REPOSITORY: &str = env!("CARGO_PKG_REPOSITORY");

/// The downloader used by `fat data install --release`.
///
/// Only this explicit command uses the network; analysis commands never do.
fn download_to_path(url: &str, destination: &Path) -> Result<(), String> {
    let destination = destination
        .to_str()
        .ok_or_else(|| "download destination is not valid UTF-8".to_string())?;
    let mut failures = Vec::new();
    for (program, arguments) in [
        (
            "curl",
            vec![
                "--fail",
                "--location",
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                "--silent",
                "--show-error",
                "--output",
                destination,
                url,
            ],
        ),
        (
            "wget",
            vec![
                "--https-only",
                "--quiet",
                "--output-document",
                destination,
                url,
            ],
        ),
    ] {
        match std::process::Command::new(program).args(arguments).status() {
            Ok(status) if status.success() => return Ok(()),
            Ok(status) => failures.push(format!("{program} exited with {status}")),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                failures.push(format!("{program} is not installed"))
            }
            Err(error) => failures.push(format!("{program} failed: {error}")),
        }
        let _ = fs::remove_file(destination);
    }
    Err(format!(
        "install curl or wget to download the FAT data release ({})",
        failures.join("; ")
    ))
}

fn install_release(root: &Path, json: bool) -> DynResult<()> {
    install_release_with(root, json, &download_to_path)
}

fn install_release_with(
    root: &Path,
    json: bool,
    fetch: &dyn Fn(&str, &Path) -> Result<(), String>,
) -> DynResult<()> {
    let version = env!("CARGO_PKG_VERSION");
    let release = format!("{RELEASE_REPOSITORY}/releases/download/v{version}");
    let archive_name = format!("fat-data-{version}.zip");
    let archive_url = format!("{release}/{archive_name}");
    let checksum_url = format!("{archive_url}.sha256");

    let temporary = tempfile::tempdir()?;
    let archive = temporary.path().join(&archive_name);
    let checksum = temporary.path().join(format!("{archive_name}.sha256"));

    eprintln!("Downloading {archive_url}");
    fetch(&archive_url, &archive)
        .map_err(|error| format!("failed to download {archive_url}: {error}"))?;
    fetch(&checksum_url, &checksum)
        .map_err(|error| format!("failed to download {checksum_url}: {error}"))?;

    let expected = read_checksum(&checksum)?;
    let actual = sha256_file(&archive)?;
    if expected != actual {
        return Err(format!(
            "FAT data archive SHA-256 mismatch: {archive_url} lists {expected}, downloaded archive is {actual}"
        )
        .into());
    }

    install(&archive, root, json)
}

/// Read the release checksum asset, which holds either a bare digest or the
/// `digest  filename` form used by the platform archives.
fn read_checksum(path: &Path) -> DynResult<String> {
    let text = fs::read_to_string(path)?;
    let digest = text
        .split_whitespace()
        .next()
        .ok_or("FAT data checksum file is empty")?;
    if digest.len() != 64 || !digest.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(format!(
            "FAT data checksum file at {} does not contain a SHA-256 digest",
            path.display()
        )
        .into());
    }
    Ok(digest.to_ascii_lowercase())
}

fn sha256_file(path: &Path) -> DynResult<String> {
    let mut file = File::open(path)?;
    let mut hasher = Sha256::new();
    io::copy(&mut file, &mut hasher)?;
    Ok(format!("{:x}", hasher.finalize()))
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

    fn sha256_hex(bytes: &[u8]) -> String {
        format!("{:x}", Sha256::digest(bytes))
    }

    /// Build a minimal verified data archive and return its digest.
    fn write_data_archive(path: &Path, data_version: &str) -> String {
        let payload = b"profile: sample\n";
        let manifest = serde_json::json!({
            "schema_version": fat_core::data_manifest::SUPPORTED_DATA_SCHEMA_VERSION,
            "data_version": data_version,
            "compatible_fat": format!("={}", env!("CARGO_PKG_VERSION")),
            "files": [
                {"path": "payload.txt", "sha256": sha256_hex(payload), "required": true}
            ],
        });
        let file = File::create(path).unwrap();
        let mut archive = zip::ZipWriter::new(file);
        let options = zip::write::SimpleFileOptions::default();
        archive.start_file(DATA_MANIFEST_FILE, options).unwrap();
        archive
            .write_all(serde_json::to_string_pretty(&manifest).unwrap().as_bytes())
            .unwrap();
        archive.start_file("payload.txt", options).unwrap();
        archive.write_all(payload).unwrap();
        archive.finish().unwrap();
        sha256_hex(&fs::read(path).unwrap())
    }

    #[test]
    fn release_install_downloads_verifies_and_activates() {
        let workspace = tempfile::tempdir().unwrap();
        let archive = workspace.path().join("fat-data.zip");
        let checksum = format!("{}\n", write_data_archive(&archive, "9.9.9"));
        let fetch = |url: &str, destination: &Path| -> Result<(), String> {
            if url.ends_with(".sha256") {
                fs::write(destination, &checksum).map_err(|error| error.to_string())
            } else {
                fs::copy(&archive, destination)
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            }
        };
        let root = workspace.path().join("managed");

        install_release_with(&root, false, &fetch).unwrap();

        assert_eq!(
            fs::read_to_string(root.join("versions/9.9.9/payload.txt")).unwrap(),
            "profile: sample\n"
        );
        let active = fs::read_to_string(root.join("active.json")).unwrap();
        assert!(active.contains("versions/9.9.9"), "{active}");
    }

    #[test]
    fn release_install_rejects_checksum_mismatch() {
        let workspace = tempfile::tempdir().unwrap();
        let archive = workspace.path().join("fat-data.zip");
        write_data_archive(&archive, "9.9.9");
        let fetch = |url: &str, destination: &Path| -> Result<(), String> {
            if url.ends_with(".sha256") {
                fs::write(destination, format!("{}\n", "0".repeat(64)))
                    .map_err(|error| error.to_string())
            } else {
                fs::copy(&archive, destination)
                    .map(|_| ())
                    .map_err(|error| error.to_string())
            }
        };

        let error = install_release_with(&workspace.path().join("managed"), false, &fetch)
            .expect_err("a checksum mismatch must stop installation");

        assert!(error.to_string().contains("SHA-256 mismatch"), "{error}");
        assert!(!workspace.path().join("managed/versions").exists());
    }

    #[test]
    fn checksum_asset_accepts_bare_and_named_digests() {
        let workspace = tempfile::tempdir().unwrap();
        let path = workspace.path().join("fat-data-2.0.1.zip.sha256");
        let digest = "a".repeat(64);
        fs::write(&path, format!("{digest}\n")).unwrap();
        assert_eq!(read_checksum(&path).unwrap(), digest);
        fs::write(&path, format!("{digest}  fat-data-2.0.1.zip\n")).unwrap();
        assert_eq!(read_checksum(&path).unwrap(), digest);
        fs::write(&path, "not a digest\n").unwrap();
        assert!(read_checksum(&path).is_err());
    }
}
