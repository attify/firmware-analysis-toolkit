use std::collections::VecDeque;
use std::fs;
use std::io::{self, Cursor, Read};
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::archive;
use crate::cramfs::{extract_cramfs, CramfsLimits};
use crate::output::{ExtractionLimits, ExtractionStats, OutputTree};
use crate::squashfs;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactStatus {
    Recovered,
    Unsupported,
    Failed,
    Limited,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactRecord {
    pub id: usize,
    pub parent: Option<usize>,
    pub source: PathBuf,
    pub offset: u64,
    pub size: u64,
    pub format: String,
    pub decoder: String,
    pub status: ArtifactStatus,
    pub output: Option<PathBuf>,
    pub stats: ExtractionStats,
    pub detail: Option<String>,
    pub duration_ms: u64,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PipelineReport {
    pub artifacts: Vec<ArtifactRecord>,
    pub truncated: bool,
}

impl PipelineReport {
    pub fn has_unresolved(&self) -> bool {
        self.truncated
            || self
                .artifacts
                .iter()
                .any(|a| a.status != ArtifactStatus::Recovered)
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PipelineOptions {
    pub limits: ExtractionLimits,
    pub max_input_bytes: u64,
    pub max_container_depth: usize,
    pub max_artifacts: usize,
}

impl Default for PipelineOptions {
    fn default() -> Self {
        Self {
            limits: ExtractionLimits::default(),
            max_input_bytes: 512 * 1024 * 1024,
            max_container_depth: 8,
            max_artifacts: 4096,
        }
    }
}

struct WorkItem {
    path: PathBuf,
    parent: Option<usize>,
    depth: usize,
}

#[derive(Clone, Copy)]
enum Format {
    Zip,
    Tar,
    Gzip,
    Squashfs,
    Cramfs,
}

impl Format {
    fn label(self) -> &'static str {
        match self {
            Self::Zip => "zip",
            Self::Tar => "tar",
            Self::Gzip => "gzip",
            Self::Squashfs => "squashfs",
            Self::Cramfs => "cramfs",
        }
    }
}

pub fn extract(
    input: &Path,
    destination: &Path,
    options: PipelineOptions,
) -> io::Result<PipelineReport> {
    if options.max_artifacts == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "artifact budget must be positive",
        ));
    }
    let scanner =
        aho_corasick::AhoCorasick::new(SIGNATURES.iter().map(|(signature, _)| *signature))
            .map_err(io::Error::other)?;
    let mut queue = VecDeque::from([WorkItem {
        path: input.to_path_buf(),
        parent: None,
        depth: 0,
    }]);
    let mut report = PipelineReport::default();
    let mut remaining = options.limits;
    let mut cramfs_count = 0;
    let mut gzip_count = 0;
    while let Some(item) = queue.pop_front() {
        if report.artifacts.len() >= options.max_artifacts {
            report.truncated = true;
            return Ok(report);
        }
        let read_result = (|| -> io::Result<Vec<u8>> {
            if item.depth > options.max_container_depth {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "container depth budget exceeded",
                ));
            }
            if fs::metadata(&item.path)?.len() > options.max_input_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "input size budget exceeded",
                ));
            }
            let mut bytes = Vec::new();
            fs::File::open(&item.path)?
                .take(options.max_input_bytes.saturating_add(1))
                .read_to_end(&mut bytes)?;
            if bytes.len() as u64 > options.max_input_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "input size budget exceeded",
                ));
            }
            Ok(bytes)
        })();
        let bytes = match read_result {
            Ok(bytes) => bytes,
            Err(error) => {
                report.artifacts.push(ArtifactRecord {
                    id: report.artifacts.len(),
                    parent: item.parent,
                    source: item.path,
                    offset: 0,
                    size: 0,
                    format: "uninspected".into(),
                    decoder: "native".into(),
                    status: error_status(&error),
                    output: None,
                    stats: ExtractionStats::default(),
                    detail: Some(error.to_string()),
                    duration_ms: 0,
                });
                continue;
            }
        };
        let whole = if bytes.starts_with(b"PK\x03\x04") || bytes.starts_with(b"PK\x05\x06") {
            Some(Format::Zip)
        } else if archive::is_tar(&bytes) {
            Some(Format::Tar)
        } else {
            None
        };
        let mut cursor = 0;
        loop {
            let next = if let Some(format) = whole {
                (cursor == 0).then_some((0, format))
            } else {
                next_region(&scanner, &bytes, cursor)
            };
            let Some((offset, format)) = next else {
                break;
            };
            let id = report.artifacts.len();
            if id >= options.max_artifacts {
                report.truncated = true;
                return Ok(report);
            }
            let path = match format {
                Format::Squashfs => destination
                    .join(format!("{id:04}-{offset:08x}"))
                    .join("squashfs-root"),
                Format::Cramfs => {
                    cramfs_count += 1;
                    destination.join(if cramfs_count == 1 {
                        "cramfs-root".into()
                    } else {
                        format!("cramfs-root-{cramfs_count}")
                    })
                }
                Format::Gzip => {
                    gzip_count += 1;
                    destination.join(if gzip_count == 1 {
                        "kernel".into()
                    } else {
                        format!("kernel-{gzip_count}")
                    })
                }
                _ => destination.join(format!("{id:04}-{}", format.label())),
            };
            let mut record = ArtifactRecord {
                id,
                parent: item.parent,
                source: item.path.clone(),
                offset: offset as u64,
                size: (bytes.len() - offset) as u64,
                format: format.label().into(),
                decoder: format!("native-{}", format.label()),
                status: ArtifactStatus::Failed,
                output: None,
                stats: ExtractionStats::default(),
                detail: None,
                duration_ms: 0,
            };
            let started = Instant::now();
            let result = decode(format, &bytes[offset..], &path, remaining, &mut record);
            record.duration_ms = started.elapsed().as_millis().min(u64::MAX as u128) as u64;
            cursor = offset + 4;
            match result {
                Ok(children) => {
                    remaining.max_output_bytes = remaining
                        .max_output_bytes
                        .saturating_sub(record.stats.bytes);
                    remaining.max_entries =
                        remaining.max_entries.saturating_sub(record.stats.entries());
                    record.status = ArtifactStatus::Recovered;
                    record.output = Some(path.clone());
                    cursor = offset.saturating_add(record.size as usize).max(cursor);
                    let mut children = children;
                    children.sort();
                    queue.extend(children.into_iter().map(|child| WorkItem {
                        path: path.join(child),
                        parent: Some(id),
                        depth: item.depth + 1,
                    }));
                }
                Err(error) => {
                    record.status = error_status(&error);
                    record.detail = Some(error.to_string());
                }
            }
            report.artifacts.push(record);
        }
    }
    Ok(report)
}

const SIGNATURES: &[(&[u8], Format)] = &[
    (b"hsqs", Format::Squashfs),
    (b"sqsh", Format::Squashfs),
    (b"qshs", Format::Squashfs),
    (b"shsq", Format::Squashfs),
    (b"sqlz", Format::Squashfs),
    (b"hsqt", Format::Squashfs),
    (b"tqsh", Format::Squashfs),
    (b"\x45\x3d\xcd\x28", Format::Cramfs),
    (b"\x28\xcd\x3d\x45", Format::Cramfs),
    (b"\x1f\x8b\x08", Format::Gzip),
];

fn next_region(
    scanner: &aho_corasick::AhoCorasick,
    bytes: &[u8],
    mut start: usize,
) -> Option<(usize, Format)> {
    while let Some(tail) = bytes.get(start..) {
        let matched = scanner.find(tail)?;
        let offset = start + matched.start();
        let format = SIGNATURES[matched.pattern().as_usize()].1;
        let candidate = &bytes[offset..];
        let plausible = match format {
            Format::Squashfs => candidate.get(28..32).is_some_and(|version| {
                let little = u16::from_le_bytes([version[0], version[1]]);
                let big = u16::from_be_bytes([version[0], version[1]]);
                ((1..=16).contains(&little) && u16::from_le_bytes([version[2], version[3]]) <= 16)
                    || ((1..=16).contains(&big)
                        && u16::from_be_bytes([version[2], version[3]]) <= 16)
            }),
            Format::Gzip => candidate.len() >= 10 && candidate[3] & 0xe0 == 0,
            Format::Cramfs => candidate.get(16..32) == Some(b"Compressed ROMFS"),
            _ => true,
        };
        if offset == 0 || plausible {
            return Some((offset, format));
        }
        start += matched.end();
    }
    None
}

fn error_status(error: &io::Error) -> ArtifactStatus {
    if error.kind() == io::ErrorKind::Unsupported {
        ArtifactStatus::Unsupported
    } else if error.to_string().contains("budget") || error.to_string().contains("limit") {
        ArtifactStatus::Limited
    } else {
        ArtifactStatus::Failed
    }
}

fn decode(
    format: Format,
    bytes: &[u8],
    path: &Path,
    limits: ExtractionLimits,
    record: &mut ArtifactRecord,
) -> io::Result<Vec<PathBuf>> {
    if matches!(format, Format::Cramfs) {
        let size_bytes: [u8; 4] = bytes
            .get(4..8)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated CramFS header"))?
            .try_into()
            .unwrap();
        let size = if bytes.starts_with(b"\x45\x3d\xcd\x28") {
            u32::from_le_bytes(size_bytes)
        } else {
            u32::from_be_bytes(size_bytes)
        };
        let image = bytes
            .get(..size as usize)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "truncated CramFS image"))?;
        let result = extract_cramfs(
            image,
            path,
            CramfsLimits {
                max_inodes: limits.max_entries.min(u32::MAX as u64) as u32,
                max_depth: limits.max_depth as u32,
                max_file_size: limits.max_file_bytes,
                max_total_output: limits.max_output_bytes,
            },
        )
        .map_err(io::Error::other)?;
        record.size = size as u64;
        record.stats = ExtractionStats {
            files: result.files,
            directories: result.directories,
            symlinks: result.symlinks,
            skipped_special: result.skipped_special,
            bytes: result.bytes,
        };
        return Ok(Vec::new());
    }
    let mut output = OutputTree::new(path, limits)?;
    let children = match format {
        Format::Zip => archive::unpack_zip(bytes, &mut output)?,
        Format::Tar => archive::unpack_tar(bytes, &mut output)?,
        Format::Gzip => {
            let mut decoder = flate2::bufread::GzDecoder::new(Cursor::new(bytes));
            let name = decoder
                .header()
                .and_then(|header| header.filename())
                .and_then(|name| std::str::from_utf8(name).ok())
                .filter(|name| {
                    !name.is_empty()
                        && !name.contains(['/', '\\', '\0'])
                        && !matches!(*name, "." | "..")
                })
                .unwrap_or("decompressed.bin")
                .to_string();
            output.write_reader(Path::new(&name), &mut decoder, 0o644)?;
            record.size = decoder.into_inner().position();
            output.write_file(
                Path::new(&format!("{name}.gz")),
                &bytes[..record.size as usize],
                0o644,
            )?;
            vec![PathBuf::from(name)]
        }
        Format::Squashfs => {
            let info = squashfs::probe(bytes)?;
            record.size = info.image_size;
            let info = squashfs::extract(bytes, &mut output)?;
            record.detail = Some(format!(
                "version {}, {} endian, {}",
                info.version, info.endianness, info.compression
            ));
            Vec::new()
        }
        Format::Cramfs => unreachable!(),
    };
    record.stats = output.finish()?;
    Ok(children)
}
