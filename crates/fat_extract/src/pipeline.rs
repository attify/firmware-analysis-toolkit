use std::collections::VecDeque;
use std::fs;
use std::io::{self, Cursor, Read};
use std::path::{Path, PathBuf};
use std::time::Instant;

use serde::{Deserialize, Serialize};

use crate::cramfs::{extract_cramfs, CramfsLimits};
use crate::output::{ExtractionLimits, ExtractionStats, OutputTree};
use crate::squashfs;
use crate::{archive, jffs2};

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
    snapshot: Option<PathBuf>,
    parent: Option<usize>,
    depth: usize,
}

struct ChildInput {
    path: PathBuf,
    snapshot: Option<PathBuf>,
}

impl From<PathBuf> for ChildInput {
    fn from(path: PathBuf) -> Self {
        Self {
            path,
            snapshot: None,
        }
    }
}

#[derive(Clone, Copy)]
enum Format {
    Zip,
    Tar,
    Gzip,
    Squashfs,
    Cramfs,
    Jffs2,
}

impl Format {
    fn label(self) -> &'static str {
        match self {
            Self::Zip => "zip",
            Self::Tar => "tar",
            Self::Gzip => "gzip",
            Self::Squashfs => "squashfs",
            Self::Cramfs => "cramfs",
            Self::Jffs2 => "jffs2",
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
    // Private disk snapshots avoid retaining reconstructed files in RAM or
    // changing firmware permissions merely to inspect nested containers.
    let snapshots = tempfile::tempdir()?;
    let mut queue = VecDeque::from([WorkItem {
        path: input.to_path_buf(),
        snapshot: None,
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
            let read_path = item.snapshot.as_ref().unwrap_or(&item.path);
            if fs::metadata(read_path)?.len() > options.max_input_bytes {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "input size budget exceeded",
                ));
            }
            let mut bytes = Vec::new();
            fs::File::open(read_path)?
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
        if let Some(snapshot) = &item.snapshot {
            // TempDir also cleans up queued snapshots on early termination.
            let _ = fs::remove_file(snapshot);
        }
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
                Format::Jffs2 => destination
                    .join(format!("{id:04}-{offset:08x}"))
                    .join("jffs2-root"),
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
            let result = decode(
                format,
                &bytes[offset..],
                &path,
                remaining,
                &mut record,
                snapshots.path(),
            );
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
                    children.sort_by(|a, b| a.path.cmp(&b.path));
                    queue.extend(children.into_iter().map(|child| WorkItem {
                        path: path.join(child.path),
                        snapshot: child.snapshot,
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
    (b"\x85\x19", Format::Jffs2),
    (b"\x19\x85", Format::Jffs2),
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
            Format::Jffs2 => jffs2::plausible(candidate),
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
    snapshots: &Path,
) -> io::Result<Vec<ChildInput>> {
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
    let mut snapshot_guard = None;
    let children = match format {
        Format::Zip => archive::unpack_zip(bytes, &mut output)?
            .into_iter()
            .map(ChildInput::from)
            .collect(),
        Format::Tar => archive::unpack_tar(bytes, &mut output)?
            .into_iter()
            .map(ChildInput::from)
            .collect(),
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
            vec![PathBuf::from(name).into()]
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
        Format::Jffs2 => {
            let cache = tempfile::tempdir_in(snapshots)?;
            let recovered = jffs2::extract(bytes, &mut output, cache.path())?;
            snapshot_guard = Some(cache);
            record.size = recovered.size as u64;
            recovered
                .children
                .into_iter()
                .map(|(path, snapshot)| ChildInput {
                    path,
                    snapshot: Some(snapshot),
                })
                .collect()
        }
        Format::Cramfs => unreachable!(),
    };
    record.stats = output.finish()?;
    if let Some(cache) = snapshot_guard {
        // Failed decodes drop their copies immediately. Successful copies stay
        // within the pipeline-owned temporary root until the queue reads them.
        let _ = cache.keep();
    }
    Ok(children)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn jffs2_crc(bytes: &[u8]) -> u32 {
        let mut hasher = crc32fast::Hasher::new_with_initial(u32::MAX);
        hasher.update(bytes);
        hasher.finalize() ^ u32::MAX
    }

    fn node(kind: u16, size: usize) -> Vec<u8> {
        let mut node = vec![0; size];
        node[..2].copy_from_slice(&0x1985u16.to_le_bytes());
        node[2..4].copy_from_slice(&kind.to_le_bytes());
        node[4..8].copy_from_slice(&(size as u32).to_le_bytes());
        let crc = jffs2_crc(&node[..8]);
        node[8..12].copy_from_slice(&crc.to_le_bytes());
        node
    }

    #[test]
    fn failed_jffs2_decode_removes_temporary_file_copies() {
        let mut image = Vec::new();
        // The first file is reconstructed and copied before the second file's
        // unsupported codec fails. None of those copies may survive the attempt.
        for (ino, name, codec) in [(2u32, b'a', 0u8), (3, b'b', 7)] {
            let mut entry = node(0xe001, 41);
            entry[12..16].copy_from_slice(&1u32.to_le_bytes());
            entry[16..20].copy_from_slice(&ino.to_le_bytes());
            entry[20..24].copy_from_slice(&ino.to_le_bytes());
            entry[28] = 1;
            entry[40] = name;
            let crc = jffs2_crc(&entry[..32]);
            entry[32..36].copy_from_slice(&crc.to_le_bytes());
            entry[36..40].copy_from_slice(&jffs2_crc(&[name]).to_le_bytes());
            image.extend(entry);
            image.resize((image.len() + 3) & !3, 0xff);
            let mut data = node(0xe002, 71);
            for (offset, value) in [
                (12, ino),
                (16, 1),
                (20, 0o100644),
                (28, 3),
                (48, 3),
                (52, 3),
            ] {
                data[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
            }
            data[56] = codec;
            data[68..].copy_from_slice(b"abc");
            data[60..64].copy_from_slice(&jffs2_crc(b"abc").to_le_bytes());
            let crc = jffs2_crc(&data[..60]);
            data[64..68].copy_from_slice(&crc.to_le_bytes());
            image.extend(data);
            image.resize((image.len() + 3) & !3, 0xff);
        }
        let root = tempfile::tempdir().unwrap();
        let snapshots = tempfile::tempdir().unwrap();
        let output = root.path().join("output");
        let mut record = ArtifactRecord {
            id: 0,
            parent: None,
            source: "fixture".into(),
            offset: 0,
            size: image.len() as u64,
            format: "jffs2".into(),
            decoder: "native-jffs2".into(),
            status: ArtifactStatus::Failed,
            output: None,
            stats: ExtractionStats::default(),
            detail: None,
            duration_ms: 0,
        };
        let error = decode(
            Format::Jffs2,
            &image,
            &output,
            ExtractionLimits::default(),
            &mut record,
            snapshots.path(),
        )
        .err()
        .expect("unsupported codec must fail");
        assert_eq!(error.kind(), io::ErrorKind::Unsupported);
        assert!(!output.exists());
        assert_eq!(fs::read_dir(snapshots.path()).unwrap().count(), 0);
    }
}
