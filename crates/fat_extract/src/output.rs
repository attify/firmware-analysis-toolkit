use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, Read, Write};
use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct ExtractionLimits {
    pub max_entries: u64,
    pub max_file_bytes: u64,
    pub max_output_bytes: u64,
    pub max_depth: usize,
}

impl Default for ExtractionLimits {
    fn default() -> Self {
        Self {
            max_entries: 262_144,
            max_file_bytes: 256 * 1024 * 1024,
            max_output_bytes: 1024 * 1024 * 1024,
            max_depth: 64,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtractionStats {
    pub files: u64,
    pub directories: u64,
    pub symlinks: u64,
    pub skipped_special: u64,
    pub bytes: u64,
}

impl ExtractionStats {
    pub fn entries(&self) -> u64 {
        self.files + self.directories + self.symlinks + self.skipped_special
    }
}

enum Entry {
    Directory(u32),
    File,
    Symlink(PathBuf),
}

pub struct OutputTree {
    destination: PathBuf,
    staging: tempfile::TempDir,
    entries: BTreeMap<PathBuf, Entry>,
    limits: ExtractionLimits,
    stats: ExtractionStats,
}

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

impl OutputTree {
    pub fn new(destination: &Path, limits: ExtractionLimits) -> io::Result<Self> {
        if destination.symlink_metadata().is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "output already exists",
            ));
        }
        if limits.max_entries == 0 {
            return Err(invalid("entry budget exceeded"));
        }
        let parent = destination
            .parent()
            .filter(|p| !p.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        fs::create_dir_all(parent)?;
        let staging = tempfile::Builder::new()
            .prefix(".extract-")
            .tempdir_in(parent)?;
        Ok(Self {
            destination: destination.to_path_buf(),
            staging,
            entries: BTreeMap::from([(PathBuf::new(), Entry::Directory(0o755))]),
            limits,
            stats: ExtractionStats {
                directories: 1,
                ..Default::default()
            },
        })
    }

    pub fn limits(&self) -> ExtractionLimits {
        self.limits
    }

    pub fn stats(&self) -> &ExtractionStats {
        &self.stats
    }

    fn normalize(&self, path: &Path) -> io::Result<PathBuf> {
        let mut result = PathBuf::new();
        for component in path.components() {
            match component {
                Component::Normal(name) => result.push(name),
                Component::CurDir => {}
                _ => return Err(invalid("output path leaves the extraction tree")),
            }
        }
        if result.components().count() > self.limits.max_depth {
            return Err(invalid("path depth budget exceeded"));
        }
        Ok(result)
    }

    fn reserve_entry(&self) -> io::Result<()> {
        if self.stats.entries() >= self.limits.max_entries {
            return Err(invalid("entry budget exceeded"));
        }
        Ok(())
    }

    fn parents(&mut self, path: &Path) -> io::Result<()> {
        if let Some(parent) = path.parent() {
            match self.entries.get(parent) {
                Some(Entry::Directory(_)) => {}
                Some(_) => return Err(invalid("output parent is not a directory")),
                None => self.create_dir(parent, 0o755)?,
            }
        }
        Ok(())
    }

    pub fn create_dir(&mut self, relative: &Path, mode: u32) -> io::Result<()> {
        let path = self.normalize(relative)?;
        match self.entries.get_mut(&path) {
            Some(Entry::Directory(existing)) => {
                *existing = mode;
                return Ok(());
            }
            Some(_) => return Err(invalid("output directory collides with another entry")),
            None => {}
        }
        self.parents(&path)?;
        self.reserve_entry()?;
        fs::create_dir(self.staging.path().join(&path))
            .map_err(|error| output_error(error, &path))?;
        self.entries.insert(path, Entry::Directory(mode));
        self.stats.directories += 1;
        Ok(())
    }

    pub fn write_file(&mut self, relative: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
        if bytes.len() as u64 > self.limits.max_file_bytes
            || bytes.len() as u64
                > self
                    .limits
                    .max_output_bytes
                    .saturating_sub(self.stats.bytes)
        {
            return Err(invalid("output byte budget exceeded"));
        }
        self.write_reader(relative, bytes, mode).map(|_| ())
    }

    pub fn write_reader(
        &mut self,
        relative: &Path,
        mut reader: impl Read,
        mode: u32,
    ) -> io::Result<u64> {
        let path = self.normalize(relative)?;
        if self.entries.contains_key(&path) {
            return Err(invalid("duplicate output entry"));
        }
        self.parents(&path)?;
        self.reserve_entry()?;
        let destination = self.staging.path().join(&path);
        let mut file =
            File::create_new(&destination).map_err(|error| output_error(error, &path))?;
        let budget = self.limits.max_file_bytes.min(
            self.limits
                .max_output_bytes
                .saturating_sub(self.stats.bytes),
        );
        let result = (|| {
            let mut buffer = [0u8; 64 * 1024];
            let mut count = 0;
            loop {
                let read = reader.read(&mut buffer)?;
                if read == 0 {
                    break;
                }
                if read as u64 > budget.saturating_sub(count) {
                    return Err(invalid("output byte budget exceeded"));
                }
                file.write_all(&buffer[..read])?;
                count += read as u64;
            }
            set_mode(&destination, mode)?;
            Ok(count)
        })();
        drop(file);
        match result {
            Ok(count) => {
                self.entries.insert(path, Entry::File);
                self.stats.files += 1;
                self.stats.bytes += count;
                Ok(count)
            }
            Err(error) => {
                let _ = fs::remove_file(destination);
                Err(error)
            }
        }
    }

    pub fn write_symlink(&mut self, relative: &Path, target: &Path) -> io::Result<()> {
        let length = target.as_os_str().len() as u64;
        if length > 4096
            || length > self.limits.max_file_bytes
            || length
                > self
                    .limits
                    .max_output_bytes
                    .saturating_sub(self.stats.bytes)
        {
            return Err(invalid("symlink target exceeds output byte budget"));
        }
        let path = self.normalize(relative)?;
        if self.entries.contains_key(&path) {
            return Err(invalid("duplicate output entry"));
        }
        self.parents(&path)?;
        self.reserve_entry()?;
        self.entries
            .insert(path, Entry::Symlink(target.to_path_buf()));
        self.stats.symlinks += 1;
        self.stats.bytes += length;
        Ok(())
    }

    pub fn skip_special(&mut self) -> io::Result<()> {
        self.reserve_entry()?;
        self.stats.skipped_special += 1;
        Ok(())
    }

    pub fn finish(self) -> io::Result<ExtractionStats> {
        for (path, entry) in &self.entries {
            if let Entry::Symlink(target) = entry {
                #[cfg(unix)]
                std::os::unix::fs::symlink(target, self.staging.path().join(path))
                    .map_err(|error| output_error(error, path))?;
                #[cfg(not(unix))]
                {
                    let _ = (target, path);
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        "symlink output requires Unix",
                    ));
                }
            }
        }
        for (path, entry) in self.entries.iter().rev() {
            if let Entry::Directory(mode) = entry {
                set_mode(&self.staging.path().join(path), *mode)?;
            }
        }
        if self.destination.symlink_metadata().is_ok() {
            return Err(io::Error::new(
                io::ErrorKind::AlreadyExists,
                "output already exists",
            ));
        }
        fs::rename(self.staging.path(), &self.destination)?;
        Ok(self.stats)
    }
}

fn output_error(error: io::Error, path: &Path) -> io::Error {
    if error.kind() == io::ErrorKind::AlreadyExists {
        io::Error::new(error.kind(), format!("host filesystem cannot represent distinct output names at {}; use a case-sensitive output volume", path.display()))
    } else {
        error
    }
}

fn set_mode(path: &Path, mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(mode & 0o777))?;
    }
    #[cfg(not(unix))]
    let _ = (path, mode);
    Ok(())
}
