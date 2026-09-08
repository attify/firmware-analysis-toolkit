use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use fat_core::database::ProjectDb;
use fat_core::project::Project;

type DynResult<T> = Result<T, Box<dyn Error>>;

pub fn run(
    project_dir: Option<&Path>,
    firmware_path: Option<&Path>,
    offset: &str,
    format: &str,
) -> DynResult<()> {
    let source = resolve_source(project_dir, firmware_path)?;
    let offset = parse_offset(offset)?;

    if !source.firmware_path.is_file() {
        return Err(format!(
            "firmware path does not exist or is not a file: {}",
            source.firmware_path.display()
        )
        .into());
    }

    let bytes = fs::read(&source.firmware_path)?;
    if offset as usize >= bytes.len() {
        return Err(format!(
            "offset 0x{offset:08X} is outside the firmware file ({} bytes)",
            bytes.len()
        )
        .into());
    }

    let payload = match format {
        "lzma" => decompress_lzma_alone(&bytes[offset as usize..])?,
        other => {
            return Err(format!("unsupported payload format: {other}").into());
        }
    };

    let output_dir = match source.mode {
        SourceMode::Project => source.root.join("work").join("payloads"),
        SourceMode::File => source
            .root
            .join(".fat-payloads")
            .join(slugify_name(&source.firmware_path)),
    };
    fs::create_dir_all(&output_dir)?;

    let output_path = output_dir.join(format!("{format}-0x{offset:08X}.bin"));
    fs::write(&output_path, &payload)?;

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
                palette.kv("format", palette.muted(format!("{format} · decompressed"))),
                palette.kv("size", crate::format_size(payload.len() as u64))
            ),
            palette.kv("output", output_path.display().to_string()),
        ];
        println!("{}", palette.panel("fat extract-payload", &lines));
        println!(
            "{}",
            palette.next_hint(&format!("fat inspect --file {}", output_path.display()))
        );
    } else {
        println!("source: {}", source.firmware_path.display());
        println!("offset: 0x{offset:08X}");
        println!("format: {format}");
        println!("output: {}", output_path.display());
        println!("size: {}", payload.len());
    }

    Ok(())
}

struct PayloadSource {
    mode: SourceMode,
    root: PathBuf,
    firmware_path: PathBuf,
}

enum SourceMode {
    Project,
    File,
}

fn resolve_source(
    project_dir: Option<&Path>,
    firmware_path: Option<&Path>,
) -> DynResult<PayloadSource> {
    match (project_dir, firmware_path) {
        (Some(project_dir), None) => {
            let project_dir = normalize_project_dir(project_dir)?;
            let db = ProjectDb::open(&project_dir)?;
            let project = load_project(&db, &project_dir)?;
            Ok(PayloadSource {
                mode: SourceMode::Project,
                root: project_dir.clone(),
                firmware_path: project_dir.join("input").join(project.firmware_name),
            })
        }
        (None, Some(firmware_path)) => {
            let root = firmware_path
                .parent()
                .ok_or_else(|| format!("firmware path has no parent: {}", firmware_path.display()))?
                .to_path_buf();
            Ok(PayloadSource {
                mode: SourceMode::File,
                root,
                firmware_path: firmware_path.to_path_buf(),
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

fn parse_offset(value: &str) -> DynResult<u64> {
    if let Some(hex) = value
        .strip_prefix("0x")
        .or_else(|| value.strip_prefix("0X"))
    {
        return Ok(u64::from_str_radix(hex, 16)?);
    }
    Ok(value.parse::<u64>()?)
}

fn decompress_lzma_alone(input: &[u8]) -> DynResult<Vec<u8>> {
    use xz2::stream::{Action, Status, Stream};

    // An embedded LZMA-alone payload ends at its own stream boundary; the
    // remaining firmware bytes belong to the caller, not to the decoder.
    let mut decoder = Stream::new_lzma_decoder(u64::MAX)?;
    let mut output = Vec::new();
    let mut chunk = [0; 8192];
    loop {
        let before_in = decoder.total_in();
        let before_out = decoder.total_out();
        let status = decoder.process(&input[before_in as usize..], &mut chunk, Action::Finish)?;
        let produced = (decoder.total_out() - before_out) as usize;
        output.extend_from_slice(&chunk[..produced]);
        if status == Status::StreamEnd {
            return Ok(output);
        }
        if decoder.total_in() == before_in && produced == 0 {
            return Err("incomplete LZMA payload: stream did not reach its end".into());
        }
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn compressed() -> (Vec<u8>, Vec<u8>) {
        let payload = b"synthetic embedded kernel payload\n".repeat(1024);
        let mut compressed = Vec::new();
        lzma_rs::lzma_compress(&mut Cursor::new(&payload), &mut compressed).unwrap();
        (payload, compressed)
    }

    #[test]
    fn lzma_payload_stops_before_trailing_bytes() {
        let (expected, compressed) = compressed();
        for suffix in [vec![], vec![0; 77], vec![0xff; 77], compressed.clone()] {
            let mut input = compressed.clone();
            input.extend(suffix);
            assert_eq!(decompress_lzma_alone(&input).unwrap(), expected);
        }
    }

    #[test]
    fn lzma_payload_rejects_truncation_and_invalid_header() {
        let (_, compressed) = compressed();
        for len in [0, 12, compressed.len() / 2, compressed.len() - 1] {
            assert!(
                decompress_lzma_alone(&compressed[..len]).is_err(),
                "length {len}"
            );
        }
        let mut invalid = compressed;
        invalid[0] = 0xff;
        assert!(decompress_lzma_alone(&invalid).is_err());
    }

    #[test]
    fn extracts_embedded_lzma_at_nonzero_offset() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("firmware.bin");
        let (expected, compressed) = compressed();
        let mut image = vec![0xa5; 128];
        image.extend(compressed);
        image.extend([0xff; 77]);
        fs::write(&source, image).unwrap();
        run(None, Some(&source), "0x80", "lzma").unwrap();
        assert_eq!(
            fs::read(
                temp.path()
                    .join(".fat-payloads/firmware/lzma-0x00000080.bin")
            )
            .unwrap(),
            expected
        );
    }
}
