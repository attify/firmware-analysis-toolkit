use std::io;

use super::{
    invalid,
    metadata::{Position, Reader},
    unsupported,
};

pub(super) struct Inode {
    pub mode: u32,
    pub kind: Kind,
}

pub(super) enum Kind {
    Directory {
        block: u64,
        offset: usize,
        size: usize,
    },
    File {
        start: u64,
        size: u64,
        fragment: u32,
        fragment_offset: usize,
        blocks: Position,
    },
    Symlink(Vec<u8>),
    Special,
}

pub(super) fn read(reader: &mut Reader<'_>, reference: u64, max_file: u64) -> io::Result<Inode> {
    let mut position = reader.inode_position(reference)?;
    let endian = reader.header.endian;
    let major = reader.header.major;
    let base_size = match major {
        4 => 16,
        3 => 12,
        _ => 4,
    };
    let base = reader.read(&mut position, base_size)?;
    let (kind, mode) = if major == 4 {
        (
            endian.uint(&base, 0, 2)? as u16,
            endian.uint(&base, 2, 2)? as u32,
        )
    } else {
        (
            endian.bits(&base, 0, 4)? as u16,
            endian.bits(&base, 4, 12)? as u32,
        )
    };
    let tail_length = match (major, kind) {
        (4, 1 | 2) => 16,
        (4, 8) => 24,
        (4, 9) => 40,
        (4, 3 | 10) => 8,
        (3, 1) => 16,
        (3, 8) => 19,
        (3, 2) => 20,
        (3, 9) => 28,
        (3, 3) => 6,
        (2, 1) => 11,
        (2, 8) => 14,
        (2, 2) => 20,
        (2, 3) => 2,
        (_, 4..=7) | (4, 11..=14) => {
            return Ok(Inode {
                mode,
                kind: Kind::Special,
            })
        }
        _ => return Err(unsupported(format!("SquashFS {major} inode type {kind}"))),
    };
    let tail = reader.read(&mut position, tail_length)?;
    let get = |offset, width| endian.uint(&tail, offset, width);
    let bits = |offset, width| endian.bits(&tail, offset, width);
    let kind = match (major, kind) {
        (4, 1) => directory(get(0, 4)?, get(10, 2)?, get(8, 2)?, true)?,
        (4, 8) => directory(get(8, 4)?, get(18, 2)?, get(4, 4)?, true)?,
        (3, 1) => directory(get(8, 4)?, bits(51, 13)?, bits(32, 19)?, true)?,
        (3, 8) => directory(get(9, 4)?, bits(59, 13)?, bits(32, 27)?, true)?,
        (2, 1) => directory(bits(64, 24)?, bits(19, 13)?, bits(0, 19)?, false)?,
        (2, 8) => directory(bits(72, 24)?, bits(27, 13)?, bits(0, 27)?, false)?,
        (4, 2) => file(
            get(0, 4)?,
            get(12, 4)?,
            get(4, 4)?,
            get(8, 4)?,
            position,
            max_file,
        )?,
        (4, 9) => file(
            get(0, 8)?,
            get(8, 8)?,
            get(28, 4)?,
            get(32, 4)?,
            position,
            max_file,
        )?,
        (3, 2) => file(
            get(0, 8)?,
            get(16, 4)?,
            get(8, 4)?,
            get(12, 4)?,
            position,
            max_file,
        )?,
        (3, 9) => file(
            get(4, 8)?,
            get(20, 8)?,
            get(12, 4)?,
            get(16, 4)?,
            position,
            max_file,
        )?,
        (2, 2) => file(
            get(4, 4)?,
            get(16, 4)?,
            get(8, 4)?,
            get(12, 4)?,
            position,
            max_file,
        )?,
        (_, 3) | (4, 10) => {
            let size = match major {
                4 => get(4, 4)?,
                3 => get(4, 2)?,
                _ => get(0, 2)?,
            };
            if size == 0 || size > 65535 || size > max_file {
                return Err(invalid("SquashFS symlink exceeds size limit"));
            }
            Kind::Symlink(reader.read(&mut position, size as usize)?)
        }
        _ => unreachable!(),
    };
    Ok(Inode { mode, kind })
}

fn directory(block: u64, offset: u64, size: u64, bias: bool) -> io::Result<Kind> {
    let size = if bias {
        size.checked_sub(3)
            .ok_or_else(|| invalid("invalid SquashFS directory size"))?
    } else {
        size
    };
    Ok(Kind::Directory {
        block,
        offset: offset as usize,
        size: size as usize,
    })
}

fn file(
    start: u64,
    size: u64,
    fragment: u64,
    fragment_offset: u64,
    blocks: Position,
    max_file: u64,
) -> io::Result<Kind> {
    if size > max_file || size > usize::MAX as u64 {
        return Err(invalid("SquashFS file exceeds output size limit"));
    }
    Ok(Kind::File {
        start,
        size,
        fragment: fragment as u32,
        fragment_offset: fragment_offset as usize,
        blocks,
    })
}
