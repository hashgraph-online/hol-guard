#![forbid(unsafe_code)]

use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::os::fd::AsFd;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock, TryLockError, Weak};

use nix::fcntl::{openat, AtFlags, OFlag};
use nix::sys::stat::{fstatat, Mode};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct DirectoryIdentity {
    device: u64,
    inode: u64,
}

#[derive(Debug)]
pub(crate) enum DirectoryLockError {
    Open,
    Invalid,
    NotPrivate,
    Busy,
    Failed,
    PathReplaced,
}

struct DirectoryLockInner {
    file: File,
    path: PathBuf,
    identity: DirectoryIdentity,
    transition: Mutex<()>,
}

impl Drop for DirectoryLockInner {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

#[derive(Clone)]
pub(crate) struct DirectoryLock(Arc<DirectoryLockInner>);

pub(crate) struct DirectoryTransitionGuard<'a> {
    _guard: MutexGuard<'a, ()>,
}

struct DirectoryRegistry {
    by_identity: HashMap<DirectoryIdentity, Weak<DirectoryLockInner>>,
    by_path: HashMap<PathBuf, Weak<DirectoryLockInner>>,
}

static REGISTRY: OnceLock<Mutex<DirectoryRegistry>> = OnceLock::new();

fn registry() -> &'static Mutex<DirectoryRegistry> {
    REGISTRY.get_or_init(|| {
        Mutex::new(DirectoryRegistry {
            by_identity: HashMap::new(),
            by_path: HashMap::new(),
        })
    })
}

fn path_identity(path: &Path) -> Result<(PathBuf, DirectoryIdentity), DirectoryLockError> {
    let canonical = fs::canonicalize(path).map_err(|_| DirectoryLockError::Invalid)?;
    let opened = fs::symlink_metadata(path).map_err(|_| DirectoryLockError::Invalid)?;
    let canonical_metadata =
        fs::symlink_metadata(&canonical).map_err(|_| DirectoryLockError::Invalid)?;
    if opened.file_type().is_symlink()
        || !opened.is_dir()
        || canonical_metadata.file_type().is_symlink()
        || !canonical_metadata.is_dir()
        || opened.dev() != canonical_metadata.dev()
        || opened.ino() != canonical_metadata.ino()
        || opened.permissions().mode() & 0o077 != 0
    {
        return Err(DirectoryLockError::PathReplaced);
    }
    Ok((
        canonical,
        DirectoryIdentity {
            device: opened.dev(),
            inode: opened.ino(),
        },
    ))
}

fn open_verified_directory(
    path: &Path,
) -> Result<(File, PathBuf, DirectoryIdentity), DirectoryLockError> {
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC);
    let file = options.open(path).map_err(|_| DirectoryLockError::Open)?;
    let opened = file.metadata().map_err(|_| DirectoryLockError::Invalid)?;
    let path_metadata = fs::symlink_metadata(path).map_err(|_| DirectoryLockError::Invalid)?;
    if !opened.is_dir()
        || path_metadata.file_type().is_symlink()
        || !path_metadata.is_dir()
        || opened.dev() != path_metadata.dev()
        || opened.ino() != path_metadata.ino()
    {
        return Err(DirectoryLockError::Invalid);
    }
    if opened.permissions().mode() & 0o077 != 0 {
        return Err(DirectoryLockError::NotPrivate);
    }
    let (canonical, identity) = path_identity(path)?;
    if identity.device != opened.dev() || identity.inode != opened.ino() {
        return Err(DirectoryLockError::PathReplaced);
    }
    Ok((file, canonical, identity))
}

fn same_live_lock(
    weak: Option<&Weak<DirectoryLockInner>>,
    identity: DirectoryIdentity,
    path: &Path,
) -> Result<Option<DirectoryLock>, DirectoryLockError> {
    let Some(inner) = weak.and_then(Weak::upgrade) else {
        return Ok(None);
    };
    if inner.identity != identity || inner.path != path {
        return Err(DirectoryLockError::PathReplaced);
    }
    Ok(Some(DirectoryLock(inner)))
}

pub(crate) fn acquire(path: &Path) -> Result<DirectoryLock, DirectoryLockError> {
    let (file, canonical, identity) = open_verified_directory(path)?;
    let mut entries = registry().lock().map_err(|_| DirectoryLockError::Failed)?;

    if let Some(lock) = same_live_lock(entries.by_path.get(&canonical), identity, &canonical)? {
        return Ok(lock);
    }
    if let Some(lock) = same_live_lock(entries.by_identity.get(&identity), identity, &canonical)? {
        return Ok(lock);
    }
    entries.by_path.remove(&canonical);
    entries.by_identity.remove(&identity);

    fs2::FileExt::try_lock_exclusive(&file).map_err(|error| {
        if crate::resident_state::is_lock_contention(&error) {
            DirectoryLockError::Busy
        } else {
            DirectoryLockError::Failed
        }
    })?;
    let inner = Arc::new(DirectoryLockInner {
        file,
        path: canonical.clone(),
        identity,
        transition: Mutex::new(()),
    });
    entries.by_path.insert(canonical, Arc::downgrade(&inner));
    entries.by_identity.insert(identity, Arc::downgrade(&inner));
    Ok(DirectoryLock(inner))
}

impl DirectoryLock {
    pub(crate) fn revalidate(&self) -> Result<(), DirectoryLockError> {
        let (_, identity) = path_identity(&self.0.path)?;
        if identity != self.0.identity {
            return Err(DirectoryLockError::PathReplaced);
        }
        Ok(())
    }

    pub(crate) fn open_child_file(&self, name: &str) -> Result<File, DirectoryLockError> {
        if name.is_empty() || name == "." || name == ".." || name.contains('/') {
            return Err(DirectoryLockError::Invalid);
        }
        self.revalidate()?;
        let fd = openat(
            self.0.file.as_fd(),
            name,
            OFlag::O_CLOEXEC | OFlag::O_NOFOLLOW | OFlag::O_CREAT | OFlag::O_RDWR,
            Mode::from_bits_truncate(0o600),
        )
        .map_err(|_| DirectoryLockError::Open)?;
        let file = File::from(fd);
        let opened = file.metadata().map_err(|_| DirectoryLockError::Invalid)?;
        let named = fstatat(self.0.file.as_fd(), name, AtFlags::AT_SYMLINK_NOFOLLOW)
            .map_err(|_| DirectoryLockError::Invalid)?;
        let parent = self
            .0
            .file
            .metadata()
            .map_err(|_| DirectoryLockError::Invalid)?;
        if !opened.is_file()
            || named.st_mode as u64 & libc::S_IFMT as u64 != libc::S_IFREG as u64
            || opened.dev() != named.st_dev as u64
            || opened.ino() != named.st_ino
            || opened.nlink() != 1
            || opened.permissions().mode() & 0o077 != 0
            || opened.uid() != parent.uid()
        {
            return Err(DirectoryLockError::Invalid);
        }
        self.revalidate()?;
        Ok(file)
    }

    pub(crate) fn try_transition(
        &self,
    ) -> Result<DirectoryTransitionGuard<'_>, DirectoryLockError> {
        self.revalidate()?;
        let guard = match self.0.transition.try_lock() {
            Ok(guard) => guard,
            Err(TryLockError::WouldBlock) => return Err(DirectoryLockError::Busy),
            Err(TryLockError::Poisoned(_)) => return Err(DirectoryLockError::Failed),
        };
        self.revalidate()?;
        Ok(DirectoryTransitionGuard { _guard: guard })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn root(label: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "hol-guard-state-directory-lock-{label}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        root
    }

    #[test]
    fn last_reference_retains_kernel_barrier() {
        let root = root("retention");
        let first = acquire(&root).unwrap();
        let last = first.clone();
        drop(first);
        let probe = OpenOptions::new().read(true).open(&root).unwrap();
        assert!(fs2::FileExt::try_lock_exclusive(&probe).is_err());
        drop(last);
        fs2::FileExt::try_lock_exclusive(&probe).unwrap();
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn path_replacement_is_rejected_while_barrier_is_live() {
        let root = root("replacement");
        let old = root.with_extension("old");
        let lock = acquire(&root).unwrap();
        fs::rename(&root, &old).unwrap();
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o700)).unwrap();
        assert!(matches!(
            acquire(&root),
            Err(DirectoryLockError::PathReplaced)
        ));
        assert!(matches!(
            lock.try_transition(),
            Err(DirectoryLockError::PathReplaced)
        ));
        drop(lock);
        fs::remove_dir_all(root).unwrap();
        fs::remove_dir_all(old).unwrap();
    }
}
