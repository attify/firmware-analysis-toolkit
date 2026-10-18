//! Bounded JFFS2 reconstruction before scanning file contents for nested containers.
//!
//! On-disk fields follow Linux's include/uapi/linux/jffs2.h. A region is a run
//! of nodes separated by at most one 64 KiB erased gap; this is not a flash
//! partition-size detector. Unsupported codecs and incomplete files stay unresolved.
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::io::{self, Read};
use std::path::{Path, PathBuf};

use crate::output::OutputTree;

#[derive(Clone, Copy)]
enum Endian {
    Little,
    Big,
}

impl Endian {
    fn u16(self, bytes: &[u8]) -> u16 {
        let bytes = bytes[..2].try_into().unwrap();
        match self {
            Self::Little => u16::from_le_bytes(bytes),
            Self::Big => u16::from_be_bytes(bytes),
        }
    }

    fn u32(self, bytes: &[u8]) -> u32 {
        let bytes = bytes[..4].try_into().unwrap();
        match self {
            Self::Little => u32::from_le_bytes(bytes),
            Self::Big => u32::from_be_bytes(bytes),
        }
    }
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn unsupported(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message.into())
}

fn crc(bytes: &[u8]) -> u32 {
    let mut hash = crc32fast::Hasher::new_with_initial(u32::MAX);
    hash.update(bytes);
    hash.finalize() ^ u32::MAX
}

fn byte_order(bytes: &[u8]) -> io::Result<Endian> {
    match bytes.get(..2) {
        Some(b"\x85\x19") => Ok(Endian::Little),
        Some(b"\x19\x85") => Ok(Endian::Big),
        _ => Err(invalid("invalid JFFS2 magic")),
    }
}

// Obsoleting a node clears NODE_ACCURATE in flash without changing its CRC.
fn header(bytes: &[u8], endian: Endian) -> io::Result<(u16, usize)> {
    let raw = bytes
        .get(..12)
        .ok_or_else(|| invalid("truncated JFFS2 header"))?;
    if endian.u16(raw) != 0x1985 {
        return Err(invalid("inconsistent JFFS2 byte order"));
    }
    let kind = endian.u16(&raw[2..]);
    let size = endian.u32(&raw[4..]) as usize;
    let mut accurate = raw[..8].to_vec();
    let kind_bytes = match endian {
        Endian::Little => (kind | 0x2000).to_le_bytes(),
        Endian::Big => (kind | 0x2000).to_be_bytes(),
    };
    accurate[2..4].copy_from_slice(&kind_bytes);
    if size < 12 || crc(&accurate) != endian.u32(&raw[8..]) {
        return Err(invalid("invalid JFFS2 node length or header CRC"));
    }
    Ok((kind, size))
}

pub(crate) fn plausible(bytes: &[u8]) -> bool {
    byte_order(bytes).and_then(|e| header(bytes, e)).is_ok()
}

struct Fragment<'a> {
    version: u32,
    mode: u32,
    size: usize,
    offset: usize,
    decoded_size: usize,
    compression: u8,
    data: &'a [u8],
}

struct Dirent {
    version: u32,
    ino: u32,
}

pub(crate) struct Recovery {
    pub size: usize,
    pub children: Vec<(PathBuf, PathBuf)>,
}

pub(crate) fn extract(
    bytes: &[u8],
    output: &mut OutputTree,
    snapshots: &Path,
) -> io::Result<Recovery> {
    std::fs::create_dir_all(snapshots)?;
    let endian = byte_order(bytes)?;
    let limits = output.limits();
    let mut inodes: BTreeMap<u32, Vec<Fragment<'_>>> = BTreeMap::new();
    let mut dirents: BTreeMap<(u32, String), Dirent> = BTreeMap::new();
    let mut cursor = 0;
    let mut extent = 0;
    let mut nodes = 0u64;
    while cursor < bytes.len() {
        if bytes[cursor] == 0xff {
            let erased = bytes[cursor..]
                .iter()
                .take(65_537)
                .take_while(|&&b| b == 0xff)
                .count();
            if erased > 65_536 || cursor + erased == bytes.len() {
                break;
            }
            cursor += erased;
        }
        if !matches!(
            bytes.get(cursor..cursor + 2),
            Some(b"\x85\x19" | b"\x19\x85")
        ) {
            break;
        }
        nodes += 1;
        if nodes > limits.max_entries {
            return Err(invalid("JFFS2 node budget exceeded"));
        }
        let (kind, size) = header(&bytes[cursor..], endian)?;
        let node = bytes
            .get(cursor..cursor.saturating_add(size))
            .ok_or_else(|| invalid("truncated JFFS2 node"))?;
        extent = cursor + size;
        cursor = cursor.saturating_add(size.saturating_add(3) & !3);
        if kind & 0x2000 == 0 {
            continue;
        }
        match kind {
            0x2003 | 0x2004 => {} // Clean marker or padding.
            0xe001 => {
                if node.len() < 40 || crc(&node[..32]) != endian.u32(&node[32..]) {
                    return Err(invalid("invalid JFFS2 dirent node CRC or length"));
                }
                let name = &node[40..];
                if name.len() != usize::from(node[28]) || crc(name) != endian.u32(&node[36..]) {
                    return Err(invalid("invalid JFFS2 dirent name CRC or length"));
                }
                let name = std::str::from_utf8(name)
                    .map_err(|_| unsupported("non-UTF-8 JFFS2 filename"))?;
                if name.is_empty() || matches!(name, "." | "..") || name.contains(['/', '\\', '\0'])
                {
                    return Err(invalid("unsafe JFFS2 directory entry"));
                }
                let key = (endian.u32(&node[12..]), name.to_owned());
                let value = Dirent {
                    version: endian.u32(&node[16..]),
                    ino: endian.u32(&node[20..]),
                };
                if let Some(old) = dirents.get(&key) {
                    if old.version == value.version && old.ino != value.ino {
                        return Err(invalid("conflicting JFFS2 dirent versions"));
                    }
                    if old.version > value.version {
                        continue;
                    }
                }
                dirents.insert(key, value);
            }
            0xe002 => {
                if node.len() < 68 || crc(&node[..60]) != endian.u32(&node[64..]) {
                    return Err(invalid("invalid JFFS2 inode node CRC or length"));
                }
                let data = &node[68..];
                if data.len() != endian.u32(&node[48..]) as usize
                    || crc(data) != endian.u32(&node[60..])
                {
                    return Err(invalid("invalid JFFS2 inode data CRC or length"));
                }
                let fragment = Fragment {
                    version: endian.u32(&node[16..]),
                    mode: endian.u32(&node[20..]),
                    size: endian.u32(&node[28..]) as usize,
                    offset: endian.u32(&node[44..]) as usize,
                    decoded_size: endian.u32(&node[52..]) as usize,
                    compression: node[56],
                    data,
                };
                if fragment.size as u64 > limits.max_file_bytes
                    || fragment.size as u64 > limits.max_output_bytes
                {
                    return Err(invalid("JFFS2 inode size exceeds output byte budget"));
                }
                if fragment
                    .offset
                    .checked_add(fragment.decoded_size)
                    .is_none_or(|end| end > fragment.size)
                {
                    return Err(invalid("JFFS2 fragment exceeds inode size"));
                }
                inodes
                    .entry(endian.u32(&node[12..]))
                    .or_default()
                    .push(fragment);
            }
            _ => {
                return Err(unsupported(format!(
                    "unsupported JFFS2 node type {kind:#06x}"
                )))
            }
        }
    }
    if extent == 0 {
        return Err(invalid("no complete JFFS2 nodes"));
    }
    for fragments in inodes.values_mut() {
        fragments.sort_by_key(|f| f.version);
        for pair in fragments.windows(2) {
            if pair[0].version == pair[1].version
                && (
                    pair[0].mode,
                    pair[0].size,
                    pair[0].offset,
                    pair[0].decoded_size,
                    pair[0].compression,
                    pair[0].data,
                ) != (
                    pair[1].mode,
                    pair[1].size,
                    pair[1].offset,
                    pair[1].decoded_size,
                    pair[1].compression,
                    pair[1].data,
                )
            {
                return Err(invalid("conflicting JFFS2 inode versions"));
            }
        }
    }
    let has_root_dirent = dirents.keys().any(|(parent, _)| *parent == 1);
    let mut directories: BTreeMap<u32, Vec<(String, u32)>> = BTreeMap::new();
    for ((parent, name), entry) in dirents {
        if entry.ino != 0 {
            directories
                .entry(parent)
                .or_default()
                .push((name, entry.ino));
        }
    }
    let mut queue = VecDeque::from([(1u32, PathBuf::new())]);
    let mut visited = BTreeSet::new();
    let mut children = Vec::new();
    let mut work_budget = limits.max_output_bytes;
    while let Some((ino, path)) = queue.pop_front() {
        if !visited.insert(ino) {
            return Err(invalid(
                "JFFS2 directory cycle or multiple directory parents",
            ));
        }
        if path.components().count() > limits.max_depth {
            return Err(invalid("JFFS2 path depth budget exceeded"));
        }
        let mode = inodes
            .get(&ino)
            .and_then(|f| f.last())
            .map_or(0o40755, |f| f.mode);
        if mode & 0o170000 != 0o040000 {
            return Err(invalid("JFFS2 directory has a non-directory inode"));
        }
        output.create_dir(&path, mode)?;
        for (name, child_ino) in directories.remove(&ino).unwrap_or_default() {
            let child_path = path.join(name);
            let fragments = inodes
                .get(&child_ino)
                .ok_or_else(|| invalid("missing JFFS2 inode for live dirent"))?;
            let latest = fragments.last().unwrap();
            match latest.mode & 0o170000 {
                0o040000 => queue.push_back((child_ino, child_path)),
                0o100000 | 0o120000 => {
                    let data = reconstruct(fragments, &mut work_budget)?;
                    if latest.mode & 0o170000 == 0o120000 {
                        let target = std::str::from_utf8(&data)
                            .map_err(|_| unsupported("non-UTF-8 JFFS2 symlink"))?;
                        if target.contains('\0') {
                            return Err(invalid("NUL in JFFS2 symlink"));
                        }
                        output.write_symlink(&child_path, Path::new(target))?;
                    } else {
                        output.write_file(&child_path, &data, latest.mode)?;
                        // Preserve firmware modes in the published tree. Recursive
                        // inspection reads this private copy even if a firmware
                        // directory lacks search permission or a file is unreadable.
                        let snapshot = snapshots.join(children.len().to_string());
                        std::fs::write(&snapshot, &data)?;
                        children.push((child_path, snapshot));
                    }
                }
                _ => output.skip_special()?,
            }
        }
    }
    if !directories.is_empty()
        || (!inodes.is_empty()
            && visited.len() == 1
            && output.stats().entries() == 1
            && !inodes.contains_key(&1)
            && !has_root_dirent)
    {
        return Err(invalid("JFFS2 nodes have no complete path from the root"));
    }
    Ok(Recovery {
        size: extent,
        children,
    })
}

fn reconstruct(fragments: &[Fragment<'_>], work_budget: &mut u64) -> io::Result<Vec<u8>> {
    let mut data = Vec::new();
    let mut covered = Vec::new();
    for fragment in fragments {
        // Bound work on obsolete versions as well as the final output allocation.
        let cost =
            (fragment.size.saturating_sub(data.len()) as u64).max(fragment.decoded_size as u64);
        *work_budget = work_budget
            .checked_sub(cost)
            .ok_or_else(|| invalid("JFFS2 reconstruction byte budget exceeded"))?;
        data.resize(fragment.size, 0);
        covered.resize(fragment.size, false);
        let end = fragment.offset + fragment.decoded_size;
        let destination = &mut data[fragment.offset..end];
        match fragment.compression {
            0 | 4 => {
                if destination.len() != fragment.data.len() {
                    return Err(invalid("JFFS2 uncompressed fragment size mismatch"));
                }
                destination.copy_from_slice(fragment.data);
            }
            1 => {
                if !fragment.data.is_empty() {
                    return Err(invalid("JFFS2 zero fragment has stored data"));
                }
                destination.fill(0);
            }
            6 => {
                let mut decoder = flate2::bufread::ZlibDecoder::new(fragment.data);
                decoder.read_exact(destination)?;
                let mut extra = [0u8; 1];
                if decoder.read(&mut extra)? != 0
                    || decoder.total_in() != fragment.data.len() as u64
                {
                    return Err(invalid("JFFS2 zlib fragment size mismatch"));
                }
            }
            codec => {
                return Err(unsupported(format!(
                    "unsupported JFFS2 compression {codec}"
                )))
            }
        }
        covered[fragment.offset..end].fill(true);
    }
    if covered.iter().any(|&present| !present) {
        return Err(invalid("incomplete JFFS2 file: missing fragment ranges"));
    }
    Ok(data)
}
