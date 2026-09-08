use std::collections::{HashSet, VecDeque};
use std::fmt;
use std::fs::{self, OpenOptions};
use std::io::{self, Cursor, Read, Write};
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use flate2::bufread::ZlibDecoder;

const MAGIC: u32 = 0x28cd_3d45;
const SIGNATURE: &[u8; 16] = b"Compressed ROMFS";
const SUPER_SIZE: usize = 76;
const INODE_SIZE: usize = 12;
const BLOCK_SIZE: usize = 4_096;
const MODE_MASK: u16 = 0o170000;
const MODE_DIRECTORY: u16 = 0o040000;
const MODE_REGULAR: u16 = 0o100000;
const MODE_SYMLINK: u16 = 0o120000;
const FLAG_FSID_VERSION_2: u32 = 0x0000_0001;
const FLAG_HOLES: u32 = 0x0000_0100;
const FLAG_EXT_BLOCK_POINTERS: u32 = 0x0000_0800;
const SUPPORTED_FLAGS: u32 = 0x0000_0fff;
const BLOCK_FLAG_UNCOMPRESSED: u32 = 1 << 31;
const BLOCK_FLAG_DIRECT: u32 = 1 << 30;
const BLOCK_FLAGS: u32 = BLOCK_FLAG_UNCOMPRESSED | BLOCK_FLAG_DIRECT;

static STAGING_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, Copy)]
pub struct CramfsLimits {
    pub max_inodes: u32,
    pub max_depth: u32,
    pub max_file_size: u64,
    pub max_total_output: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CramfsExtractionResult {
    pub root: PathBuf,
    pub files: u64,
    pub directories: u64,
    pub symlinks: u64,
    pub skipped_special: u64,
}

#[derive(Debug)]
pub enum CramfsError {
    InvalidData(String),
    Io(io::Error),
}

impl fmt::Display for CramfsError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidData(message) => formatter.write_str(message),
            Self::Io(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for CramfsError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::InvalidData(_) => None,
            Self::Io(error) => Some(error),
        }
    }
}

impl From<io::Error> for CramfsError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

pub fn extract_cramfs(
    image: &[u8],
    destination: &Path,
    limits: CramfsLimits,
) -> Result<CramfsExtractionResult, CramfsError> {
    let header = Header::parse(image)?;
    if limits.max_inodes == 0 {
        return Err(invalid("CramFS inode limit must be non-zero"));
    }
    if header
        .declared_inodes
        .is_some_and(|count| count == 0 || count > limits.max_inodes)
    {
        return Err(invalid(
            "CramFS declared inode count exceeds configured limit",
        ));
    }
    if destination.exists() {
        return Err(CramfsError::Io(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("refusing to overwrite {}", destination.display()),
        )));
    }

    let parent = destination.parent().ok_or_else(|| {
        CramfsError::Io(io::Error::new(
            io::ErrorKind::InvalidInput,
            "CramFS destination has no parent",
        ))
    })?;
    fs::create_dir_all(parent)?;
    let mut staging = StagingDirectory::create(parent)?;
    let root_path = staging.path().to_path_buf();

    let mut state = ExtractionState {
        image: &image[..header.image_size],
        endian: header.endian,
        flags: header.flags,
        limits,
        inode_count: 1,
        total_output: 0,
        result: CramfsExtractionResult {
            root: destination.to_path_buf(),
            files: 0,
            directories: 1,
            symlinks: 0,
            skipped_special: 0,
        },
    };

    let root = state.read_inode(64)?;
    if root.mode & MODE_MASK != MODE_DIRECTORY || root.name_len != 0 {
        return Err(invalid("CramFS root inode is not a directory"));
    }
    state.extract_tree(root, &root_path)?;
    if header
        .declared_inodes
        .is_some_and(|count| count != state.inode_count)
    {
        return Err(invalid(
            "CramFS traversed inode count does not match the superblock",
        ));
    }

    fs::rename(staging.path(), destination)?;
    staging.commit();
    Ok(state.result)
}

#[derive(Debug, Clone, Copy)]
enum Endian {
    Little,
    Big,
}

struct Header {
    endian: Endian,
    image_size: usize,
    flags: u32,
    declared_inodes: Option<u32>,
}

impl Header {
    fn parse(image: &[u8]) -> Result<Self, CramfsError> {
        if image.len() < SUPER_SIZE || image.get(16..32) != Some(SIGNATURE) {
            return Err(invalid("invalid or truncated CramFS superblock"));
        }
        let endian = if read_u32(image, 0, Endian::Little)? == MAGIC {
            Endian::Little
        } else if read_u32(image, 0, Endian::Big)? == MAGIC {
            Endian::Big
        } else {
            return Err(invalid("CramFS magic not found"));
        };
        let image_size = usize::try_from(read_u32(image, 4, endian)?)
            .map_err(|_| invalid("CramFS image size does not fit this platform"))?;
        if image_size < SUPER_SIZE || image_size > image.len() {
            return Err(invalid("CramFS declared image size exceeds input"));
        }
        let flags = read_u32(image, 8, endian)?;
        if flags & !SUPPORTED_FLAGS != 0 {
            return Err(invalid("CramFS superblock contains unsupported flags"));
        }
        if flags & FLAG_FSID_VERSION_2 != 0 {
            let stored_crc = read_u32(image, 32, endian)?;
            let mut hasher = crc32fast::Hasher::new();
            hasher.update(&image[..32]);
            hasher.update(&[0u8; 4]);
            hasher.update(&image[36..image_size]);
            if hasher.finalize() != stored_crc {
                return Err(invalid("CramFS superblock CRC32 mismatch"));
            }
        }
        Ok(Self {
            endian,
            image_size,
            flags,
            declared_inodes: (flags & FLAG_FSID_VERSION_2 != 0)
                .then(|| read_u32(image, 44, endian))
                .transpose()?,
        })
    }
}

#[derive(Debug, Clone, Copy)]
struct Inode {
    mode: u16,
    size: u32,
    name_len: usize,
    offset: usize,
}

struct ExtractionState<'a> {
    image: &'a [u8],
    endian: Endian,
    flags: u32,
    limits: CramfsLimits,
    inode_count: u32,
    total_output: u64,
    result: CramfsExtractionResult,
}

impl ExtractionState<'_> {
    fn extract_tree(&mut self, root: Inode, root_path: &Path) -> Result<(), CramfsError> {
        let mut pending = VecDeque::from([(root, root_path.to_path_buf(), 0u32)]);
        let mut visited_directories = HashSet::new();

        while let Some((directory, path, depth)) = pending.pop_front() {
            if depth > self.limits.max_depth {
                return Err(invalid("CramFS directory depth exceeds configured limit"));
            }
            if directory.size == 0 {
                continue;
            }
            if directory.offset == 0 || !visited_directories.insert(directory.offset) {
                return Err(invalid("CramFS directory offset is zero or cyclic"));
            }
            let end = checked_end(directory.offset, directory.size as usize, self.image.len())?;
            let mut cursor = directory.offset;
            while cursor < end {
                let inode_offset = cursor;
                let child = self.read_inode(inode_offset)?;
                self.inode_count = self
                    .inode_count
                    .checked_add(1)
                    .ok_or_else(|| invalid("CramFS inode count overflow"))?;
                if self.inode_count > self.limits.max_inodes {
                    return Err(invalid("CramFS inode count exceeds configured limit"));
                }
                cursor = checked_end(cursor, INODE_SIZE, end)?;
                if child.name_len == 0 {
                    return Err(invalid("CramFS directory entry has an empty name"));
                }
                let name_end = checked_end(cursor, child.name_len, end)?;
                let padded_name = self
                    .image
                    .get(cursor..name_end)
                    .ok_or_else(|| invalid("CramFS directory name is truncated"))?;
                let name = decode_name(padded_name)?;
                cursor = name_end;
                let child_path = path.join(name);

                match child.mode & MODE_MASK {
                    MODE_DIRECTORY => {
                        fs::create_dir(&child_path)?;
                        self.result.directories += 1;
                        let child_depth = depth
                            .checked_add(1)
                            .ok_or_else(|| invalid("CramFS directory depth overflow"))?;
                        pending.push_back((child, child_path, child_depth));
                    }
                    MODE_REGULAR => {
                        let bytes = self.read_file(child)?;
                        self.add_output(bytes.len() as u64)?;
                        write_new_file(&child_path, &bytes, child.mode)?;
                        self.result.files += 1;
                    }
                    MODE_SYMLINK => {
                        let bytes = self.read_file(child)?;
                        self.add_output(bytes.len() as u64)?;
                        let target = std::str::from_utf8(&bytes)
                            .map_err(|_| invalid("CramFS symlink target is not UTF-8"))?;
                        if target.is_empty() || target.contains('\0') {
                            return Err(invalid("CramFS symlink target is empty or contains NUL"));
                        }
                        create_symlink(target, &child_path)?;
                        self.result.symlinks += 1;
                    }
                    _ => self.result.skipped_special += 1,
                }
            }
            if cursor != end {
                return Err(invalid("CramFS directory size is inconsistent"));
            }
        }
        Ok(())
    }

    fn read_inode(&self, offset: usize) -> Result<Inode, CramfsError> {
        checked_end(offset, INODE_SIZE, self.image.len())?;
        let mode_uid = read_u32(self.image, offset, self.endian)?;
        let size_gid = read_u32(self.image, offset + 4, self.endian)?;
        let name_offset = read_u32(self.image, offset + 8, self.endian)?;
        let (mode, size, name_words, offset_words) = match self.endian {
            Endian::Little => (
                mode_uid as u16,
                size_gid & 0x00ff_ffff,
                (name_offset & 0x3f) as usize,
                name_offset >> 6,
            ),
            Endian::Big => (
                (mode_uid >> 16) as u16,
                (size_gid >> 8) & 0x00ff_ffff,
                (name_offset >> 26) as usize,
                name_offset & 0x03ff_ffff,
            ),
        };
        let name_len = name_words
            .checked_mul(4)
            .ok_or_else(|| invalid("CramFS name length overflow"))?;
        let data_offset = usize::try_from(offset_words)
            .ok()
            .and_then(|value| value.checked_mul(4))
            .ok_or_else(|| invalid("CramFS inode offset overflow"))?;
        Ok(Inode {
            mode,
            size,
            name_len,
            offset: data_offset,
        })
    }

    fn read_file(&self, inode: Inode) -> Result<Vec<u8>, CramfsError> {
        let file_size = u64::from(inode.size);
        if file_size > self.limits.max_file_size {
            return Err(invalid("CramFS file size exceeds configured limit"));
        }
        if inode.size == 0 {
            if inode.offset != 0 {
                return Err(invalid("empty CramFS file has a non-zero offset"));
            }
            return Ok(Vec::new());
        }
        if inode.offset == 0 {
            return Err(invalid("non-empty CramFS file has a zero offset"));
        }

        let blocks = (inode.size as usize).div_ceil(BLOCK_SIZE);
        let table_size = blocks
            .checked_mul(4)
            .ok_or_else(|| invalid("CramFS block table size overflow"))?;
        let table_end = checked_end(inode.offset, table_size, self.image.len())?;
        let mut block_start = table_end;
        let mut output = Vec::with_capacity(inode.size as usize);

        for block_index in 0..blocks {
            let raw_pointer = read_u32(self.image, inode.offset + block_index * 4, self.endian)?;
            if raw_pointer & BLOCK_FLAGS != 0 && self.flags & FLAG_EXT_BLOCK_POINTERS == 0 {
                return Err(invalid(
                    "CramFS block pointer extensions are not declared by the superblock",
                ));
            }
            if raw_pointer & BLOCK_FLAG_DIRECT != 0 {
                return Err(invalid("direct CramFS block pointers are not supported"));
            }
            let block_end = usize::try_from(raw_pointer & !BLOCK_FLAGS)
                .map_err(|_| invalid("CramFS block pointer does not fit this platform"))?;
            if block_end < block_start || block_end > self.image.len() {
                return Err(invalid(
                    "CramFS block pointers are decreasing or out of range",
                ));
            }
            let expected = (inode.size as usize - output.len()).min(BLOCK_SIZE);
            if block_end == block_start {
                if self.flags & FLAG_HOLES == 0 {
                    return Err(invalid(
                        "CramFS sparse block is not declared by the superblock",
                    ));
                }
                output.resize(output.len() + expected, 0);
            } else if raw_pointer & BLOCK_FLAG_UNCOMPRESSED != 0 {
                let block = self
                    .image
                    .get(block_start..block_end)
                    .ok_or_else(|| invalid("CramFS uncompressed block is truncated"))?;
                if block.len() != expected {
                    return Err(invalid("CramFS uncompressed block size mismatch"));
                }
                output.extend_from_slice(block);
            } else {
                let compressed = self
                    .image
                    .get(block_start..block_end)
                    .ok_or_else(|| invalid("CramFS compressed block is truncated"))?;
                let cursor = Cursor::new(compressed);
                let mut decoder = ZlibDecoder::new(cursor);
                let mut block = Vec::new();
                decoder
                    .by_ref()
                    .take(expected as u64 + 1)
                    .read_to_end(&mut block)
                    .map_err(|error| invalid(format!("CramFS zlib decode failed: {error}")))?;
                if decoder.get_ref().position() != compressed.len() as u64
                    || block.len() != expected
                {
                    return Err(invalid("CramFS decompressed block size mismatch"));
                }
                output.extend_from_slice(&block);
            }
            block_start = block_end;
        }
        if output.len() != inode.size as usize {
            return Err(invalid("CramFS file size mismatch"));
        }
        Ok(output)
    }

    fn add_output(&mut self, size: u64) -> Result<(), CramfsError> {
        self.total_output = self
            .total_output
            .checked_add(size)
            .ok_or_else(|| invalid("CramFS total output size overflow"))?;
        if self.total_output > self.limits.max_total_output {
            return Err(invalid("CramFS total output exceeds configured limit"));
        }
        Ok(())
    }
}

fn decode_name(padded: &[u8]) -> Result<&str, CramfsError> {
    let end = padded
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(padded.len());
    if end == 0 || padded[end..].iter().any(|byte| *byte != 0) {
        return Err(invalid("CramFS filename has invalid NUL padding"));
    }
    let name =
        std::str::from_utf8(&padded[..end]).map_err(|_| invalid("CramFS filename is not UTF-8"))?;
    if !safe_leaf_name(name) {
        return Err(invalid("CramFS filename is not a safe path component"));
    }
    Ok(name)
}

fn safe_leaf_name(name: &str) -> bool {
    if name.is_empty() || name.contains(['/', '\\', '\0']) || matches!(name, "." | "..") {
        return false;
    }
    let mut components = Path::new(name).components();
    matches!(components.next(), Some(Component::Normal(_))) && components.next().is_none()
}

fn read_u32(bytes: &[u8], offset: usize, endian: Endian) -> Result<u32, CramfsError> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| invalid("CramFS u32 field offset overflow"))?;
    let slice = bytes
        .get(offset..end)
        .ok_or_else(|| invalid("CramFS u32 field is truncated"))?;
    let raw: [u8; 4] = slice
        .try_into()
        .map_err(|_| invalid("CramFS u32 field is malformed"))?;
    Ok(match endian {
        Endian::Little => u32::from_le_bytes(raw),
        Endian::Big => u32::from_be_bytes(raw),
    })
}

fn checked_end(start: usize, length: usize, limit: usize) -> Result<usize, CramfsError> {
    let end = start
        .checked_add(length)
        .ok_or_else(|| invalid("CramFS range overflow"))?;
    if end > limit {
        Err(invalid("CramFS range exceeds the declared image"))
    } else {
        Ok(end)
    }
}

fn write_new_file(path: &Path, bytes: &[u8], mode: u16) -> Result<(), CramfsError> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    set_file_permissions(&file, mode)?;
    Ok(())
}

#[cfg(unix)]
fn set_file_permissions(file: &fs::File, mode: u16) -> Result<(), CramfsError> {
    use std::os::unix::fs::PermissionsExt;

    file.set_permissions(fs::Permissions::from_mode(u32::from(mode & 0o777)))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_file_permissions(_file: &fs::File, _mode: u16) -> Result<(), CramfsError> {
    Ok(())
}

#[cfg(unix)]
fn create_symlink(target: &str, path: &Path) -> Result<(), CramfsError> {
    std::os::unix::fs::symlink(target, path)?;
    Ok(())
}

#[cfg(not(unix))]
fn create_symlink(_target: &str, _path: &Path) -> Result<(), CramfsError> {
    Err(invalid(
        "native CramFS symlink extraction requires a Unix host",
    ))
}

struct StagingDirectory {
    path: PathBuf,
    committed: bool,
}

impl StagingDirectory {
    fn create(parent: &Path) -> Result<Self, CramfsError> {
        for _ in 0..32 {
            let sequence = STAGING_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let path = parent.join(format!(".fat-cramfs-{}-{sequence}.tmp", std::process::id()));
            match fs::create_dir(&path) {
                Ok(()) => {
                    return Ok(Self {
                        path,
                        committed: false,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(error.into()),
            }
        }
        Err(CramfsError::Io(io::Error::new(
            io::ErrorKind::AlreadyExists,
            "could not allocate a unique CramFS staging directory",
        )))
    }

    fn path(&self) -> &Path {
        &self.path
    }

    fn commit(&mut self) {
        self.committed = true;
    }
}

impl Drop for StagingDirectory {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

fn invalid(message: impl Into<String>) -> CramfsError {
    CramfsError::InvalidData(message.into())
}
