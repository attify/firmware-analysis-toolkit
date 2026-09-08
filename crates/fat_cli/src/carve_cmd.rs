use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use fat_analyze::firmware_formats::{parse_cramfs_at, parse_gzip_at, parse_squashfs_at};
use fat_core::database::ProjectDb;
use fat_core::project::Project;

type DynResult<T> = Result<T, Box<dyn Error>>;

pub fn run(
    project_dir: Option<&Path>,
    file: Option<&Path>,
    offset: &str,
    size: Option<&str>,
    format: Option<&str>,
    output: Option<&Path>,
) -> DynResult<()> {
    let source = resolve_source(project_dir, file)?;
    let offset = parse_u64(offset)?;

    if !source.firmware_path.is_file() {
        return Err(format!(
            "firmware path does not exist or is not a file: {}",
            source.firmware_path.display()
        )
        .into());
    }

    let bytes = fs::read(&source.firmware_path)?;
    let start = usize::try_from(offset).map_err(|_| "offset does not fit this platform")?;
    if start >= bytes.len() {
        return Err(format!(
            "offset 0x{offset:08X} is outside the firmware file ({} bytes)",
            bytes.len()
        )
        .into());
    }

    let inferred_format = format.unwrap_or("raw");
    let carve_size = match (format, size) {
        (Some(format @ ("squashfs" | "gzip" | "cramfs")), maybe_size) => {
            let inferred = inferred_carve_size(format, &bytes, offset)?;
            match maybe_size {
                Some(value) => parse_u64(value)?,
                None => inferred,
            }
        }
        (Some("raw") | None, Some(value)) => parse_u64(value)?,
        (Some("raw") | None, None) => {
            return Err("generic carving requires --size unless --format can infer it".into());
        }
        (Some(other), _) => return Err(format!("unsupported carve format: {other}").into()),
    };

    let end = offset
        .checked_add(carve_size)
        .ok_or("offset plus size overflows")?;
    let end_index = usize::try_from(end).map_err(|_| "carve end does not fit this platform")?;
    if end_index > bytes.len() {
        return Err(format!(
            "carve range 0x{offset:08X}..0x{end:08X} exceeds firmware file ({} bytes)",
            bytes.len()
        )
        .into());
    }

    let output_path = output
        .map(Path::to_path_buf)
        .unwrap_or_else(|| default_output_path(&source, inferred_format, offset));
    if let Some(parent) = output_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&output_path, &bytes[start..end_index])?;

    let palette = crate::style::Palette::stdout();
    if palette.enabled() {
        let lines = vec![
            format!(
                "{} {}",
                palette.dot_ok(),
                palette.good(source.firmware_path.display().to_string())
            ),
            format!(
                "{} · {} · {}",
                palette.kv("offset", format!("0x{offset:08X}")),
                palette.kv("format", inferred_format),
                palette.kv("size", crate::format_size(carve_size)),
            ),
            palette.kv("output", output_path.display().to_string()),
        ];
        println!("{}", palette.panel("fat carve", &lines));
        println!(
            "{}",
            palette.next_hint(&format!("fat inspect --file {}", output_path.display()))
        );
    } else {
        println!("source: {}", source.firmware_path.display());
        println!("offset: 0x{offset:08X}");
        println!("format: {inferred_format}");
        println!("output: {}", output_path.display());
        println!("size: {carve_size}");
    }

    Ok(())
}

struct CarveSource {
    mode: SourceMode,
    root: PathBuf,
    firmware_path: PathBuf,
}

enum SourceMode {
    Project,
    File,
}

fn resolve_source(project_dir: Option<&Path>, file: Option<&Path>) -> DynResult<CarveSource> {
    match (project_dir, file) {
        (Some(project_dir), None) => {
            let project_dir = normalize_project_dir(project_dir)?;
            let db = ProjectDb::open(&project_dir)?;
            let project = load_project(&db, &project_dir)?;
            Ok(CarveSource {
                mode: SourceMode::Project,
                root: project_dir.clone(),
                firmware_path: project_dir.join("input").join(project.firmware_name),
            })
        }
        (None, Some(file)) => {
            let root = file
                .parent()
                .ok_or_else(|| format!("firmware path has no parent: {}", file.display()))?
                .to_path_buf();
            Ok(CarveSource {
                mode: SourceMode::File,
                root,
                firmware_path: file.to_path_buf(),
            })
        }
        _ => Err(
            "exactly one input source is required: either <project> or --file <firmware.bin>"
                .into(),
        ),
    }
}

fn normalize_project_dir(project_dir: &Path) -> DynResult<PathBuf> {
    if project_dir.is_dir() {
        Ok(project_dir.to_path_buf())
    } else {
        Err(format!("project path does not exist: {}", project_dir.display()).into())
    }
}

fn load_project(db: &ProjectDb, project_dir: &Path) -> DynResult<Project> {
    let name = project_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("invalid project directory name: {}", project_dir.display()))?;

    db.get(name)?
        .ok_or_else(|| format!("project metadata not found for {}", project_dir.display()).into())
}

fn parse_u64(value: &str) -> DynResult<u64> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        return Ok(u64::from_str_radix(hex, 16)?);
    }
    Ok(value.parse::<u64>()?)
}

fn inferred_carve_size(format: &str, bytes: &[u8], offset: u64) -> DynResult<u64> {
    match format {
        "gzip" => parse_gzip_at(bytes, offset)
            .and_then(|member| member.compressed_size)
            .ok_or_else(|| "valid gzip member not found at requested offset".into()),
        "cramfs" => parse_cramfs_at(bytes, offset)
            .and_then(|header| header.image_size)
            .ok_or_else(|| "valid CramFS image not found at requested offset".into()),
        "squashfs" => parse_squashfs_at(bytes, offset)
            .and_then(|header| header.image_size)
            .ok_or_else(|| "valid SquashFS image not found at requested offset".into()),
        other => Err(format!("unsupported carve format: {other}").into()),
    }
}

fn default_output_path(source: &CarveSource, format: &str, offset: u64) -> PathBuf {
    let extension = match format {
        "squashfs" => "sqsh",
        "gzip" => "gz",
        "cramfs" => "cramfs",
        _ => "bin",
    };
    let filename = format!("{format}-0x{offset:08X}.{extension}");
    match source.mode {
        SourceMode::Project => source.root.join("work").join("carves").join(filename),
        SourceMode::File => source
            .root
            .join(".fat-carves")
            .join(slugify_name(&source.firmware_path))
            .join(filename),
    }
}

fn slugify_name(path: &Path) -> String {
    let stem = path
        .file_stem()
        .and_then(|stem| stem.to_str())
        .unwrap_or("firmware");
    let mut slug = String::new();

    for ch in stem.chars() {
        if ch.is_ascii_alphanumeric() {
            slug.push(ch.to_ascii_lowercase());
        } else if !slug.ends_with('-') {
            slug.push('-');
        }
    }

    let slug = slug.trim_matches('-');
    if slug.is_empty() {
        "firmware".to_string()
    } else {
        slug.to_string()
    }
}
