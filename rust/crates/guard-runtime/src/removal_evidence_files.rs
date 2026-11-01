//! Private files for removal evidence: created owner-only, published
//! atomically, and made durable where the platform can.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Write};
use std::path::Path;

use super::random_bytes;

/// Create `root` (and any missing parent) readable by its owner alone.
pub(super) fn private_directory(root: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(root)?;
        fs::set_permissions(root, fs::Permissions::from_mode(0o700))
    }
    #[cfg(not(unix))]
    fs::create_dir_all(root)
}

/// Write `bytes` to a file at `path` that must not exist yet; a failed write
/// leaves nothing behind.
pub(super) fn write_new_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;

        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    let written = file
        .write_all(bytes)
        .and_then(|()| file.sync_all())
        .and_then(|()| set_private_mode(path));
    if written.is_err() {
        let _ = fs::remove_file(path);
    }
    written
}

/// Publish `bytes` at `target` through a private temporary file in `root`.
pub(super) fn replace_private(
    root: &Path,
    target: &Path,
    stem: &str,
    bytes: &[u8],
) -> io::Result<()> {
    let temporary = root.join(format!(".{stem}.{}.tmp", hex::encode(random_bytes(8))));
    let published = write_new_private(&temporary, bytes)
        .and_then(|()| fs::rename(&temporary, target))
        .and_then(|()| set_private_mode(target))
        .and_then(|()| sync_directory(root));
    if let Err(error) = fs::remove_file(&temporary) {
        if error.kind() != io::ErrorKind::NotFound && published.is_ok() {
            return Err(error);
        }
    }
    published
}

fn set_private_mode(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        fs::set_permissions(path, fs::Permissions::from_mode(0o600))
    }
    #[cfg(not(unix))]
    {
        let _ = path;
        Ok(())
    }
}

#[cfg(unix)]
pub(super) fn open_without_following(path: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)
}

#[cfg(not(unix))]
pub(super) fn open_without_following(path: &Path) -> io::Result<File> {
    File::open(path)
}

/// Make a rename in `directory` durable where the platform can; a filesystem
/// that cannot sync a directory is not a failed update.
pub(super) fn sync_directory(directory: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        let unsupported = |error: &io::Error| {
            matches!(
                error.raw_os_error(),
                Some(code) if code == libc::EINVAL || code == libc::ENOTSUP
            )
        };
        match File::open(directory).and_then(|handle| handle.sync_all()) {
            Err(error) if !unsupported(&error) => Err(error),
            _ => Ok(()),
        }
    }
    #[cfg(not(unix))]
    {
        let _ = directory;
        Ok(())
    }
}
