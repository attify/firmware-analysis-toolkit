mod codec;
mod header;
mod inode;
mod metadata;

use std::collections::HashSet;
use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::output::OutputTree;
use codec::Codec;
use header::Header;
use inode::Kind;
use metadata::Reader;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SquashfsInfo {
    pub version: String,
    pub endianness: String,
    pub compression: String,
    pub image_size: u64,
    pub inode_count: u64,
}

pub fn probe(image: &[u8]) -> io::Result<SquashfsInfo> {
    let header = Header::parse(image)?;
    Ok(header.info(Codec::new(header.compression).name()))
}

pub fn extract(image: &[u8], output: &mut OutputTree) -> io::Result<SquashfsInfo> {
    let header = Header::parse(image)?;
    if header.inode_count > output.limits().max_entries {
        return Err(invalid("SquashFS inode count exceeds entry limit"));
    }
    if let Codec::Other(id) = Codec::new(header.compression) {
        return Err(unsupported(format!("SquashFS compression {id}")));
    }
    let root = header.root;
    let mut state = State {
        reader: Reader::new(image, header),
        output,
        directories: HashSet::new(),
    };
    state.visit(root, Path::new(""), 0)?;
    Ok(state.reader.header.info(state.reader.codec.name()))
}

struct State<'a, 'b> {
    reader: Reader<'a>,
    output: &'b mut OutputTree,
    directories: HashSet<u64>,
}

impl State<'_, '_> {
    fn visit(&mut self, reference: u64, path: &Path, depth: usize) -> io::Result<()> {
        if depth > self.output.limits().max_depth {
            return Err(invalid("SquashFS directory depth exceeds limit"));
        }
        let inode = inode::read(
            &mut self.reader,
            reference,
            self.output.limits().max_file_bytes,
        )?;
        if path.as_os_str().is_empty() && !matches!(inode.kind, Kind::Directory { .. }) {
            return Err(invalid("SquashFS root inode is not a directory"));
        }
        match inode.kind {
            Kind::Directory {
                block,
                offset,
                size,
            } => {
                if !self.directories.insert(reference) {
                    return Err(invalid("SquashFS directory cycle or duplicate reference"));
                }
                self.output.create_dir(path, inode.mode)?;
                let mut position = self.reader.directory_position(block, offset)?;
                let major = self.reader.header.major;
                let endian = self.reader.header.endian;
                let mut remaining = size;
                let mut names = HashSet::new();
                while remaining > 0 {
                    let header_size = match major {
                        4 => 12,
                        3 => 9,
                        _ => 4,
                    };
                    consume(&mut remaining, header_size)?;
                    let header = self.reader.read(&mut position, header_size)?;
                    let (count, start) = if major == 4 {
                        (endian.uint(&header, 0, 4)? + 1, endian.uint(&header, 4, 4)?)
                    } else {
                        (
                            header[0] as u64 + 1,
                            endian.uint(&header, 1, if major == 2 { 3 } else { 4 })?,
                        )
                    };
                    if count > 256 || count > self.output.limits().max_entries {
                        return Err(invalid("invalid SquashFS directory entry count"));
                    }
                    for _ in 0..count {
                        let entry_size = match major {
                            4 => 8,
                            3 => 5,
                            _ => 3,
                        };
                        consume(&mut remaining, entry_size)?;
                        let entry = self.reader.read(&mut position, entry_size)?;
                        let (offset, length) = if major == 4 {
                            (endian.uint(&entry, 0, 2)?, endian.uint(&entry, 6, 2)? + 1)
                        } else {
                            (endian.bits(&entry, 0, 13)?, entry[2] as u64 + 1)
                        };
                        if length > 256 {
                            return Err(invalid("SquashFS filename exceeds format limit"));
                        }
                        consume(&mut remaining, length as usize)?;
                        let name = self.reader.read(&mut position, length as usize)?;
                        if name == b"."
                            || name == b".."
                            || name.contains(&0)
                            || name.contains(&b'/')
                            || !names.insert(name.clone())
                        {
                            return Err(invalid("invalid or duplicate SquashFS filename"));
                        }
                        let child = path.join(path_bytes(name)?);
                        self.visit((start << 16) | offset, &child, depth + 1)
                            .map_err(|error| {
                                io::Error::new(
                                    error.kind(),
                                    format!("{}: {error}", child.display()),
                                )
                            })?;
                    }
                }
            }
            Kind::File {
                mut start,
                size,
                fragment,
                fragment_offset,
                mut blocks,
            } => {
                if size
                    > self
                        .output
                        .limits()
                        .max_output_bytes
                        .saturating_sub(self.output.stats().bytes)
                {
                    return Err(invalid("SquashFS file exceeds remaining output budget"));
                }
                let block_size = self.reader.header.block_size;
                let full_blocks = size as usize / block_size;
                let remainder = size as usize % block_size;
                let block_count = full_blocks + usize::from(fragment == u32::MAX && remainder != 0);
                let mut bytes = Vec::with_capacity(size as usize);
                for _ in 0..block_count {
                    let descriptor = self.reader.read(&mut blocks, 4)?;
                    let encoded = self.reader.header.endian.uint(&descriptor, 0, 4)? as u32;
                    let expected = (size as usize - bytes.len()).min(block_size);
                    let decoded = self.reader.data_block(start, encoded, expected)?;
                    if decoded.len() != expected {
                        return Err(invalid("SquashFS file block size mismatch"));
                    }
                    bytes.extend_from_slice(&decoded);
                    start = start
                        .checked_add((encoded & 0x00ff_ffff) as u64)
                        .ok_or_else(|| invalid("SquashFS block offset overflow"))?;
                }
                if fragment != u32::MAX && remainder > 0 {
                    let decoded = self.reader.fragment(fragment as u64)?;
                    let end = fragment_offset
                        .checked_add(remainder)
                        .ok_or_else(|| invalid("SquashFS fragment offset overflow"))?;
                    let tail = decoded
                        .get(fragment_offset..end)
                        .ok_or_else(|| invalid("SquashFS file tail exceeds fragment"))?;
                    bytes.extend_from_slice(tail);
                }
                if bytes.len() != size as usize {
                    return Err(invalid("SquashFS recovered file size mismatch"));
                }
                self.output.write_file(path, &bytes, inode.mode)?;
            }
            Kind::Symlink(target) => {
                if target.contains(&0) {
                    return Err(invalid("SquashFS symlink contains a NUL byte"));
                }
                self.output
                    .write_symlink(path, &PathBuf::from(path_bytes(target)?))?;
            }
            Kind::Special => self.output.skip_special()?,
        }
        Ok(())
    }
}

fn consume(remaining: &mut usize, count: usize) -> io::Result<()> {
    *remaining = remaining
        .checked_sub(count)
        .ok_or_else(|| invalid("SquashFS directory entry exceeds declared size"))?;
    Ok(())
}

#[cfg(unix)]
fn path_bytes(bytes: Vec<u8>) -> io::Result<OsString> {
    use std::os::unix::ffi::OsStringExt;
    Ok(OsString::from_vec(bytes))
}

#[cfg(not(unix))]
fn path_bytes(bytes: Vec<u8>) -> io::Result<OsString> {
    String::from_utf8(bytes)
        .map(OsString::from)
        .map_err(|_| unsupported("non-UTF-8 SquashFS path on this platform"))
}

fn invalid(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

fn unsupported(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, message.into())
}
