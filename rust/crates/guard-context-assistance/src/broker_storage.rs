//! Native-only directory capability for the SDK's bounded evidence store.
//! Product callers must derive it from their private Guard data root. It
//! carries no restored grant, source permission or execution authority.
use crate::RuntimeError;
use serde_json::{json, Value};
#[cfg(unix)]
use std::fs::File;
use std::path::{Path, PathBuf};

const CHECKPOINT_BYTES: u64 = 12 * 1024 * 1024;
const DATABASE_BYTES: u64 = 32 * 1024 * 1024;

pub struct BrokerStorage {
    directory: PathBuf,
    #[cfg(unix)]
    pub(crate) cache_owner: Option<std::sync::Arc<dyn Send + Sync>>,
    #[cfg(unix)]
    opened: File,
    #[cfg(unix)]
    database: Option<File>,
    #[cfg(unix)]
    identity: (u64, u64),
}
impl BrokerStorage {
    pub fn inspect(directory: &Path) -> Result<Self, RuntimeError> {
        #[cfg(not(unix))]
        {
            let _ = directory;
            Err(RuntimeError::PlatformUnqualified)
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
            ancestry(directory)?;
            if directory.canonicalize().map_err(unavailable)? != directory {
                return Err(RuntimeError::ScopeDenied);
            }
            let metadata = std::fs::symlink_metadata(directory).map_err(unavailable)?;
            private(&metadata, true)?;
            let opened = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(
                    (nix::fcntl::OFlag::O_DIRECTORY | nix::fcntl::OFlag::O_NOFOLLOW).bits(),
                )
                .open(directory)
                .map_err(unavailable)?;
            let observed = opened.metadata().map_err(unavailable)?;
            if (metadata.dev(), metadata.ino()) != (observed.dev(), observed.ino()) {
                return Err(RuntimeError::ContextStale);
            }
            let mut result = Self {
                directory: directory.into(),
                cache_owner: None,
                opened,
                database: None,
                identity: (metadata.dev(), metadata.ino()),
            };
            result.revalidate()?;
            if result.existed()? {
                result.seal()?;
            }
            Ok(result)
        }
    }
    pub fn revalidate(&self) -> Result<(), RuntimeError> {
        #[cfg(not(unix))]
        {
            Err(RuntimeError::PlatformUnqualified)
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            ancestry(&self.directory)?;
            for metadata in [
                std::fs::symlink_metadata(&self.directory).map_err(unavailable)?,
                self.opened.metadata().map_err(unavailable)?,
            ] {
                private(&metadata, true)?;
                if (metadata.dev(), metadata.ino()) != self.identity {
                    return Err(RuntimeError::ContextStale);
                }
            }
            for entry in std::fs::read_dir(&self.directory).map_err(unavailable)? {
                let entry = entry.map_err(unavailable)?;
                let name = entry.file_name();
                let limit = if name == "broker.sqlite3" {
                    DATABASE_BYTES
                } else if name == "broker.sqlite3-journal" {
                    DATABASE_BYTES + 1024 * 1024
                } else {
                    return Err(RuntimeError::ScopeDenied);
                };
                let metadata = std::fs::symlink_metadata(entry.path()).map_err(unavailable)?;
                private(&metadata, false)?;
                if metadata.len() > limit {
                    return Err(RuntimeError::ResourceLimit);
                }
            }
            if let Some(opened) = &self.database {
                let before = opened.metadata().map_err(unavailable)?;
                let after = std::fs::symlink_metadata(self.directory.join("broker.sqlite3"))
                    .map_err(unavailable)?;
                private(&before, false)?;
                private(&after, false)?;
                if (before.dev(), before.ino()) != (after.dev(), after.ino()) {
                    return Err(RuntimeError::ContextStale);
                }
            }
            Ok(())
        }
    }
    pub(crate) fn matches_directory(&self, path: &Path) -> Result<bool, RuntimeError> {
        self.revalidate()?;
        Ok(self.directory == path)
    }
    pub(crate) fn seal(&mut self) -> Result<(), RuntimeError> {
        self.revalidate()?;
        #[cfg(unix)]
        if self.database.is_none() {
            use std::os::unix::fs::OpenOptionsExt;
            let file = std::fs::OpenOptions::new()
                .read(true)
                .custom_flags(nix::fcntl::OFlag::O_NOFOLLOW.bits())
                .open(self.directory.join("broker.sqlite3"))
                .map_err(unavailable)?;
            let metadata = file.metadata().map_err(unavailable)?;
            private(&metadata, false)?;
            if metadata.len() == 0 {
                return Err(RuntimeError::ContextStale);
            }
            self.database = Some(file);
        }
        self.revalidate()
    }
    pub(crate) fn existed(&self) -> Result<bool, RuntimeError> {
        self.revalidate()?;
        match std::fs::symlink_metadata(self.directory.join("broker.sqlite3")) {
            Ok(_) => Ok(true),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(false),
            Err(e) => Err(unavailable(e)),
        }
    }
    pub(crate) fn wire(&self) -> Value {
        json!({"directory":self.directory,"create_directory":false,"max_checkpoint_bytes":CHECKPOINT_BYTES,
            "max_database_bytes":DATABASE_BYTES,"max_journal_records":64})
    }
}
#[cfg(unix)]
pub(crate) fn private(metadata: &std::fs::Metadata, directory: bool) -> Result<(), RuntimeError> {
    use std::os::unix::fs::MetadataExt;
    if metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.file_type().is_symlink()
        || if directory {
            !metadata.is_dir() || metadata.mode() & 0o7777 != 0o700
        } else {
            !metadata.is_file() || metadata.mode() & 0o7777 != 0o600 || metadata.nlink() != 1
        }
    {
        return Err(RuntimeError::ScopeDenied);
    }
    Ok(())
}
#[cfg(unix)]
pub(crate) fn ancestry(path: &Path) -> Result<(), RuntimeError> {
    use std::os::unix::fs::MetadataExt;
    if !path.is_absolute()
        || path.components().any(|p| {
            !matches!(
                p,
                std::path::Component::RootDir | std::path::Component::Normal(_)
            )
        })
    {
        return Err(RuntimeError::ScopeDenied);
    }
    let uid = nix::unistd::geteuid().as_raw();
    for parent in path.ancestors() {
        let m = std::fs::symlink_metadata(parent).map_err(unavailable)?;
        if !m.is_dir()
            || m.file_type().is_symlink()
            || (m.uid() != 0 && m.uid() != uid)
            || (m.mode() & 0o022 != 0 && m.mode() & 0o1000 == 0)
        {
            return Err(RuntimeError::ScopeDenied);
        }
    }
    Ok(())
}
fn unavailable(_: std::io::Error) -> RuntimeError {
    RuntimeError::ArtifactUnreadable
}

#[cfg(all(test, unix))]
#[path = "broker_storage_tests.rs"]
mod tests;
