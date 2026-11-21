//! The private cache file of `runtime-fingerprint`: one JSON file per
//! source root, read only when its directory and the file itself belong to
//! the effective user and no one else can reach them.

use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};

use super::{is_sha256_hex, Cached};
use crate::managed_resident;

/// The private-file reader's size bound, which the cache has always kept to.
#[cfg(unix)]
const MAX_CACHE_BYTES: u64 = 4096;

/// The on-disk form of the cache, keyed by the source root it describes.
/// Unknown keys are ignored.
#[derive(Deserialize)]
struct Stored {
    content_fingerprint: String,
    source_root: String,
    tree_sig: String,
}

pub(super) struct CacheFile {
    directory: PathBuf,
    path: PathBuf,
    private_root: PathBuf,
    source_root: String,
}

impl CacheFile {
    pub(super) fn new(directory: &str, source_root: &str) -> Option<Self> {
        let directory = PathBuf::from(directory);
        if !directory.is_absolute() {
            return None;
        }
        let private_root = directory.parent()?.to_path_buf();
        let name = format!(
            "{}.json",
            hex::encode(Sha256::digest(source_root.as_bytes()))
        );
        Some(Self {
            path: directory.join(name),
            directory,
            private_root,
            source_root: source_root.to_owned(),
        })
    }

    pub(super) fn load(&self) -> Option<Cached> {
        let bytes = read_cache(&self.directory, &self.path, &self.private_root)?;
        let stored: Stored = serde_json::from_slice(&bytes).ok()?;
        (stored.source_root == self.source_root && is_sha256_hex(&stored.content_fingerprint))
            .then_some(Cached {
                tree_sig: stored.tree_sig,
                fingerprint: stored.content_fingerprint,
            })
    }

    pub(super) fn store(&self, tree_sig: &str, fingerprint: &str) {
        #[cfg(not(windows))]
        {
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::DirBuilderExt;
                builder.mode(0o700);
            }
            if builder.create(&self.private_root).is_err() {
                return;
            }
        }
        if crate::resident_state::ensure_private_directory_under(
            &self.directory,
            &self.private_root,
            true,
        )
        .is_err()
        {
            return;
        }
        let body = json!({
            "content_fingerprint": fingerprint,
            "source_root": self.source_root,
            "tree_sig": tree_sig,
        });
        let _ = managed_resident::private_file::write_private(
            &self.path,
            body.to_string().as_bytes(),
            &self.private_root,
        );
    }
}

/// The cache file's bytes. The directory is opened without following a
/// final link and must be a directory the effective user owns that no one
/// else can enter; the file is then opened relative to that handle, so a
/// directory swapped after the check is never read, and it too must be a
/// private regular file the effective user owns.
#[cfg(unix)]
fn read_cache(directory: &Path, path: &Path, _private_root: &Path) -> Option<Vec<u8>> {
    use std::fs::File;
    use std::io::Read;
    use std::os::fd::AsFd;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

    use nix::fcntl::{openat, OFlag};
    use nix::sys::stat::Mode;

    let euid = nix::unistd::geteuid().as_raw();
    let private = |metadata: &fs::Metadata| {
        metadata.uid() == euid && metadata.permissions().mode() & 0o077 == 0
    };
    let handle = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory)
        .ok()?;
    let metadata = handle.metadata().ok()?;
    if !metadata.is_dir() || !private(&metadata) {
        return None;
    }
    let fd = openat(
        handle.as_fd(),
        path.file_name()?,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .ok()?;
    let file = File::from(fd);
    let metadata = file.metadata().ok()?;
    if !metadata.is_file()
        || !private(&metadata)
        || metadata.nlink() != 1
        || metadata.len() > MAX_CACHE_BYTES
    {
        return None;
    }
    let mut bytes = Vec::new();
    file.take(MAX_CACHE_BYTES + 1)
        .read_to_end(&mut bytes)
        .ok()?;
    (bytes.len() as u64 <= MAX_CACHE_BYTES).then_some(bytes)
}

#[cfg(not(unix))]
fn read_cache(directory: &Path, path: &Path, private_root: &Path) -> Option<Vec<u8>> {
    if !fs::symlink_metadata(directory).is_ok_and(|metadata| metadata.is_dir()) {
        return None;
    }
    managed_resident::private_file::read_private_bytes(
        path,
        private_root,
        "runtime_fingerprint_cache",
    )
    .ok()?
}
