use std::collections::HashMap;
use std::io;
use std::sync::Arc;

use super::{codec::Codec, header::Header, invalid};

const METADATA_LIMIT: usize = 8192;
const CACHE_LIMIT: usize = 16 * 1024 * 1024;
const CACHE_ENTRIES: usize = 8192;

#[derive(Clone, Copy)]
pub(super) struct Position {
    pub block: u64,
    pub offset: usize,
    pub end: u64,
}

struct MetadataBlock {
    bytes: Vec<u8>,
    next: u64,
}

pub(super) struct Reader<'a> {
    pub image: &'a [u8],
    pub header: Header,
    pub codec: Codec,
    metadata: HashMap<u64, Arc<MetadataBlock>>,
    fragments: HashMap<u64, Arc<Vec<u8>>>,
    cached: usize,
}

impl<'a> Reader<'a> {
    pub fn new(image: &'a [u8], header: Header) -> Self {
        let codec = Codec::new(header.compression);
        Self {
            image: &image[..header.image_size as usize],
            header,
            codec,
            metadata: HashMap::new(),
            fragments: HashMap::new(),
            cached: 0,
        }
    }

    pub fn inode_position(&self, reference: u64) -> io::Result<Position> {
        let block = self
            .header
            .inode_table
            .checked_add(reference >> 16)
            .ok_or_else(|| invalid("SquashFS inode address overflow"))?;
        let offset = (reference & 0xffff) as usize;
        if offset >= METADATA_LIMIT || block >= self.header.directory_table {
            return Err(invalid("SquashFS inode reference outside table"));
        }
        Ok(Position {
            block,
            offset,
            end: self.header.directory_table,
        })
    }

    pub fn directory_position(&self, block: u64, offset: usize) -> io::Result<Position> {
        let block = self
            .header
            .directory_table
            .checked_add(block)
            .ok_or_else(|| invalid("SquashFS directory address overflow"))?;
        if offset >= METADATA_LIMIT || block >= self.header.image_size {
            return Err(invalid("SquashFS directory reference outside image"));
        }
        Ok(Position {
            block,
            offset,
            end: self.header.image_size,
        })
    }

    pub fn read(&mut self, position: &mut Position, length: usize) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::with_capacity(length);
        while bytes.len() < length {
            let block = self.metadata_block(position.block)?;
            if block.next > position.end || position.offset > block.bytes.len() {
                return Err(invalid("SquashFS metadata reference outside table"));
            }
            let amount = (length - bytes.len()).min(block.bytes.len() - position.offset);
            bytes.extend_from_slice(&block.bytes[position.offset..position.offset + amount]);
            position.offset += amount;
            if position.offset == block.bytes.len() {
                position.block = block.next;
                position.offset = 0;
            }
        }
        Ok(bytes)
    }

    fn metadata_block(&mut self, offset: u64) -> io::Result<Arc<MetadataBlock>> {
        if let Some(block) = self.metadata.get(&offset) {
            return Ok(Arc::clone(block));
        }
        let encoded = self.header.endian.uint(self.slice(offset, 2)?, 0, 2)? as usize;
        let size = encoded & 0x7fff;
        if size == 0 || size > METADATA_LIMIT {
            return Err(invalid("invalid SquashFS metadata block size"));
        }
        let skip = if self.header.check_byte { 3 } else { 2 };
        let payload = offset
            .checked_add(skip)
            .ok_or_else(|| invalid("SquashFS metadata offset overflow"))?;
        if self.header.check_byte && self.slice(offset + 2, 1)?[0] != 0xff {
            return Err(invalid("invalid SquashFS metadata check byte"));
        }
        let input = self.slice(payload, size)?;
        let bytes = if encoded & 0x8000 != 0 {
            input.to_vec()
        } else {
            self.codec.decode(input, METADATA_LIMIT)?
        };
        if bytes.is_empty() {
            return Err(invalid("empty SquashFS metadata block"));
        }
        let block = Arc::new(MetadataBlock {
            bytes,
            next: payload + size as u64,
        });
        if self.cached + block.bytes.len() <= CACHE_LIMIT
            && self.metadata.len() + self.fragments.len() < CACHE_ENTRIES
        {
            self.cached += block.bytes.len();
            self.metadata.insert(offset, Arc::clone(&block));
        }
        Ok(block)
    }

    pub fn data_block(
        &mut self,
        offset: u64,
        encoded: u32,
        expected: usize,
    ) -> io::Result<Vec<u8>> {
        if encoded & 0xfe00_0000 != 0 {
            return Err(invalid("invalid SquashFS data block flags"));
        }
        let length = (encoded & 0x00ff_ffff) as usize;
        if (encoded != 0 && offset < self.header.superblock_size)
            || length > self.header.block_size
            || offset
                .checked_add(length as u64)
                .is_none_or(|end| end > self.header.inode_table)
        {
            return Err(invalid("SquashFS file block outside data region"));
        }
        if encoded == 0 {
            return Ok(vec![0; expected]);
        }
        let input = self.slice(offset, length)?;
        if encoded & 0x0100_0000 != 0 {
            if input.len() > expected {
                return Err(invalid("SquashFS uncompressed block exceeds expected size"));
            }
            Ok(input.to_vec())
        } else {
            self.codec.decode(input, expected)
        }
    }

    pub fn fragment(&mut self, index: u64) -> io::Result<Arc<Vec<u8>>> {
        if index >= self.header.fragments {
            return Err(invalid("SquashFS fragment index outside table"));
        }
        if let Some(bytes) = self.fragments.get(&index) {
            return Ok(Arc::clone(bytes));
        }
        let entry_size = if self.header.major == 2 { 8 } else { 16 };
        let pointer_size = if self.header.major == 2 { 4 } else { 8 };
        let table_offset = index * entry_size;
        let pointer_offset =
            self.header.fragment_table + (table_offset / METADATA_LIMIT as u64) * pointer_size;
        let block = self.header.endian.uint(
            self.slice(pointer_offset, pointer_size as usize)?,
            0,
            pointer_size as usize,
        )?;
        let mut position = Position {
            block,
            offset: table_offset as usize % METADATA_LIMIT,
            end: self.header.fragment_table,
        };
        let entry = self.read(&mut position, entry_size as usize)?;
        let start_size = if self.header.major == 2 { 4 } else { 8 };
        let start = self.header.endian.uint(&entry, 0, start_size)?;
        let encoded = self.header.endian.uint(&entry, start_size, 4)? as u32;
        let bytes = Arc::new(self.data_block(start, encoded, self.header.block_size)?);
        if self.cached + bytes.len() <= CACHE_LIMIT
            && self.metadata.len() + self.fragments.len() < CACHE_ENTRIES
        {
            self.cached += bytes.len();
            self.fragments.insert(index, Arc::clone(&bytes));
        }
        Ok(bytes)
    }

    fn slice(&self, offset: u64, length: usize) -> io::Result<&'a [u8]> {
        let start = usize::try_from(offset)
            .map_err(|_| invalid("SquashFS offset does not fit platform"))?;
        let end = start
            .checked_add(length)
            .ok_or_else(|| invalid("SquashFS range overflow"))?;
        self.image
            .get(start..end)
            .ok_or_else(|| invalid("SquashFS range exceeds input"))
    }
}
