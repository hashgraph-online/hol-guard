//! Operation-local pinned directory for discovery metadata, never hook state.
#[cfg(unix)]
use super::io::OBJECT_BYTES;
use super::io::{self, Result};
#[cfg(unix)]
use std::io::Read;
use std::{
    fs,
    path::{Path, PathBuf},
};
#[path = "catalog_cache_writer.rs"]
mod writer;

pub(crate) struct CacheReader {
    path: PathBuf,
    #[cfg(unix)]
    directory: fs::File,
    #[cfg(unix)]
    parents: Vec<(PathBuf, (u64, u64))>,
}

impl CacheReader {
    pub(crate) fn new(path: &Path) -> Result<Self> {
        Self::ancestors(path)?;
        #[cfg(unix)]
        {
            use nix::fcntl::{open, OFlag};
            use nix::sys::stat::Mode;
            use std::os::unix::fs::MetadataExt;
            let mut parents = Vec::new();
            for parent in path.ancestors().take(3) {
                let metadata = private(parent, true)?;
                parents.push((parent.into(), (metadata.dev(), metadata.ino())));
            }
            let directory = fs::File::from(
                open(
                    path,
                    OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|_| "catalog_prepare_object_unavailable")?,
            );
            let reader = Self {
                path: path.into(),
                directory,
                parents,
            };
            reader.paths()?;
            Ok(reader)
        }
        #[cfg(not(unix))]
        {
            Ok(Self { path: path.into() })
        }
    }

    fn ancestors(path: &Path) -> Result<()> {
        if !path.is_absolute()
            || path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir))
        {
            return Err("catalog_prepare_home_invalid");
        }
        for parent in path.ancestors() {
            let metadata =
                fs::symlink_metadata(parent).map_err(|_| "catalog_prepare_object_unavailable")?;
            if metadata.file_type().is_symlink() {
                return Err("catalog_prepare_symlink");
            }
        }
        Ok(())
    }

    #[cfg(unix)]
    fn paths(&self) -> Result<()> {
        use std::os::unix::fs::MetadataExt;
        for (path, identity) in &self.parents {
            let metadata = private(path, true)?;
            if (metadata.dev(), metadata.ino()) != *identity {
                return Err("catalog_prepare_directory_changed");
            }
        }
        let metadata = self
            .directory
            .metadata()
            .map_err(|_| "catalog_prepare_object_unavailable")?;
        if (metadata.dev(), metadata.ino()) != self.parents[0].1 {
            return Err("catalog_prepare_directory_changed");
        }
        Ok(())
    }

    /// Every leaf is opened relative to the pinned private directory with
    /// O_NOFOLLOW, checked for stable identity/ownership/length and SHA. Parent
    /// identities and privacy are rechecked before and after each read. Full
    /// lexical ancestry is checked at operation boundaries; path replacement
    /// cannot redirect an open directory descriptor to another object store.
    pub(crate) fn read(&self, digest: &str) -> Result<Vec<u8>> {
        #[cfg(unix)]
        self.paths()?;
        let result = self.read_pinned(digest);
        #[cfg(unix)]
        self.paths()?;
        result
    }

    /// Scan-only read through the pinned directory. The caller must finish the
    /// scan before exposing any result, so a replaced namespace fails closed.
    /// Leaf privacy, identity, length and SHA checks remain per object.
    pub(crate) fn read_pinned(&self, digest: &str) -> Result<Vec<u8>> {
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("catalog_prepare_digest_invalid");
        }
        #[cfg(unix)]
        {
            use nix::fcntl::{openat, OFlag};
            use nix::sys::stat::Mode;
            let file = fs::File::from(
                openat(
                    &self.directory,
                    format!("{digest}.json").as_str(),
                    OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
                    Mode::empty(),
                )
                .map_err(|error| {
                    if error == nix::errno::Errno::ENOENT {
                        "catalog_prepare_object_missing"
                    } else {
                        "catalog_prepare_object_unavailable"
                    }
                })?,
            );
            let before = file
                .metadata()
                .map_err(|_| "catalog_prepare_object_unavailable")?;
            private_metadata(&before, false)?;
            if before.len() == 0 {
                return Err("catalog_prepare_object_corrupt");
            }
            if before.len() > OBJECT_BYTES as u64 {
                return Err("catalog_prepare_object_budget");
            }
            let mut bytes = Vec::with_capacity(before.len() as usize);
            (&file)
                .take(OBJECT_BYTES as u64 + 1)
                .read_to_end(&mut bytes)
                .map_err(|_| "catalog_prepare_object_unavailable")?;
            let after = file
                .metadata()
                .map_err(|_| "catalog_prepare_object_unavailable")?;
            if stamp(&before) != stamp(&after) || bytes.len() != before.len() as usize {
                return Err("catalog_prepare_object_changed");
            }
            if io::hash(&bytes) != digest {
                return Err("catalog_prepare_object_corrupt");
            }
            Ok(bytes)
        }
        #[cfg(not(unix))]
        {
            let path = self.path.join(format!("{digest}.json"));
            if fs::symlink_metadata(path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
                return Err("catalog_prepare_object_missing");
            }
            io::read(&self.path, digest)
        }
    }

    pub(crate) fn finish(&self) -> Result<()> {
        Self::ancestors(&self.path)?;
        #[cfg(unix)]
        self.paths()?;
        Ok(())
    }
}

#[cfg(unix)]
fn private(path: &Path, directory: bool) -> Result<fs::Metadata> {
    let metadata = fs::symlink_metadata(path).map_err(|_| "catalog_prepare_object_unavailable")?;
    private_metadata(&metadata, directory)?;
    Ok(metadata)
}
#[cfg(unix)]
fn private_metadata(metadata: &fs::Metadata, directory: bool) -> Result<()> {
    use std::os::unix::fs::MetadataExt;
    if metadata.uid() != nix::unistd::getuid().as_raw()
        || metadata.mode() & 0o077 != 0
        || (!directory && (metadata.nlink() != 1 || metadata.mode() & 0o444 == 0))
        || (if directory {
            !metadata.is_dir()
        } else {
            !metadata.is_file()
        })
    {
        return Err("catalog_prepare_directory_not_private");
    }
    Ok(())
}
#[cfg(unix)]
fn stamp(metadata: &fs::Metadata) -> FileStamp {
    use std::os::unix::fs::MetadataExt;
    (
        metadata.dev(),
        metadata.ino(),
        metadata.mode(),
        metadata.uid(),
        metadata.gid(),
        metadata.nlink(),
        metadata.len(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}
#[cfg(unix)]
type FileStamp = (u64, u64, u32, u32, u32, u64, u64, i64, i64, i64, i64);
