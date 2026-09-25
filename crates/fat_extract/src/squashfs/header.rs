use std::io;

use super::{invalid, unsupported, SquashfsInfo};

#[derive(Clone, Copy, Debug)]
pub(super) enum Endian {
    Little,
    Big,
}

impl Endian {
    pub fn bits(self, data: &[u8], bit: usize, width: usize) -> io::Result<u64> {
        if width > 64
            || bit
                .checked_add(width)
                .is_none_or(|end| end > data.len() * 8)
        {
            return Err(invalid("truncated SquashFS field"));
        }
        let mut value = 0;
        for i in 0..width {
            let position = bit + i;
            match self {
                Self::Little => value |= (((data[position / 8] >> (position % 8)) & 1) as u64) << i,
                Self::Big => {
                    value = (value << 1) | ((data[position / 8] >> (7 - position % 8)) & 1) as u64
                }
            }
        }
        Ok(value)
    }

    pub fn uint(self, data: &[u8], offset: usize, bytes: usize) -> io::Result<u64> {
        self.bits(data, offset * 8, bytes * 8)
    }
}

pub(super) struct Header {
    pub endian: Endian,
    pub major: u16,
    pub minor: u16,
    pub inode_count: u64,
    pub image_size: u64,
    pub superblock_size: u64,
    pub block_size: usize,
    pub root: u64,
    pub inode_table: u64,
    pub directory_table: u64,
    pub fragment_table: u64,
    pub fragments: u64,
    pub check_byte: bool,
    pub compression: Option<u16>,
}

impl Header {
    pub fn parse(image: &[u8]) -> io::Result<Self> {
        let endian = match image.get(..4) {
            Some(b"hsqs" | b"shsq") => Endian::Little,
            Some(b"sqsh" | b"qshs") => Endian::Big,
            _ => return Err(invalid("SquashFS magic not found")),
        };
        let get = |offset, bytes| endian.uint(image, offset, bytes);
        let major = get(28, 2)? as u16;
        let minor = get(30, 2)? as u16;
        if !matches!((major, minor), (2, 0 | 1) | (3, 0 | 1) | (4, 0)) {
            return Err(unsupported(format!("SquashFS version {major}.{minor}")));
        }
        let (
            minimum,
            image_size,
            block_size,
            root,
            inode_table,
            directory_table,
            fragment_table,
            fragments,
            check_byte,
            compression,
            block_log,
        ) = if major == 4 {
            (
                96,
                get(40, 8)?,
                get(12, 4)?,
                get(32, 8)?,
                get(64, 8)?,
                get(72, 8)?,
                get(80, 8)?,
                get(16, 4)?,
                false,
                Some(get(20, 2)? as u16),
                get(22, 2)?,
            )
        } else {
            (
                if major == 3 { 119 } else { 63 },
                if major == 3 { get(63, 8)? } else { get(8, 4)? },
                get(51, 4)?,
                get(43, 8)?,
                if major == 3 { get(87, 8)? } else { get(20, 4)? },
                if major == 3 { get(95, 8)? } else { get(24, 4)? },
                if major == 3 {
                    get(103, 8)?
                } else {
                    get(59, 4)?
                },
                get(55, 4)?,
                get(36, 1)? & 4 != 0,
                None,
                get(34, 2)?,
            )
        };
        if image_size < minimum || image_size > image.len() as u64 {
            return Err(invalid("SquashFS declared size exceeds input"));
        }
        if !(4096..=1_048_576).contains(&block_size)
            || !block_size.is_power_of_two()
            || block_log != block_size.trailing_zeros() as u64
        {
            return Err(invalid("invalid SquashFS block size"));
        }
        let inode_count = get(4, 4)?;
        if inode_count == 0
            || inode_table < minimum
            || inode_table >= directory_table
            || directory_table >= image_size
        {
            return Err(invalid("invalid SquashFS table bounds"));
        }
        if fragments > inode_count
            || (fragments > 0 && (fragment_table < directory_table || fragment_table >= image_size))
        {
            return Err(invalid("invalid SquashFS fragment table"));
        }
        Ok(Self {
            endian,
            major,
            minor,
            inode_count,
            image_size,
            superblock_size: minimum,
            block_size: block_size as usize,
            root,
            inode_table,
            directory_table,
            fragment_table,
            fragments,
            check_byte,
            compression,
        })
    }

    pub fn info(&self, compression: &str) -> SquashfsInfo {
        SquashfsInfo {
            version: format!("{}.{}", self.major, self.minor),
            endianness: match self.endian {
                Endian::Little => "little",
                Endian::Big => "big",
            }
            .into(),
            compression: compression.into(),
            image_size: self.image_size,
            inode_count: self.inode_count,
        }
    }
}
