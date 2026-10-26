//! Re-verification of the archives a package evaluation downloaded, right
//! before a request or launch is bound to them. A download is usable only when
//! its path is still the single-link, read-only regular file that was recorded,
//! with the recorded size and SHA-256. Any doubt refuses the whole binding.

use std::fs::File;
use std::io::{ErrorKind, Read};
use std::path::Path;

use guard_contracts::{McpExternalArchiveDownloadV1, ARCHIVE_ACQUISITION_MAX_BYTES};
use sha2::{Digest, Sha256};

const CHUNK_BYTES: usize = 64 * 1024;

/// `(source url, local path)` replacements in first-seen order, or `None` when
/// any download fails verification. A repeated source URL keeps its first
/// position and takes the later path.
pub(crate) fn verified_replacements(
    downloads: &[McpExternalArchiveDownloadV1],
) -> Option<Vec<(String, String)>> {
    let mut replacements: Vec<(String, String)> = Vec::with_capacity(downloads.len());
    for download in downloads {
        // Acquisition never keeps a larger archive, so hashing stays bounded
        // on the shared evaluation workers.
        if download.size > ARCHIVE_ACQUISITION_MAX_BYTES {
            return None;
        }
        let file = open_verified(Path::new(&download.path), download.size)?;
        if !content_matches(file, download) {
            return None;
        }
        match replacements
            .iter_mut()
            .find(|(source, _)| *source == download.source_url)
        {
            Some(entry) => entry.1.clone_from(&download.path),
            None => replacements.push((download.source_url.clone(), download.path.clone())),
        }
    }
    Some(replacements)
}

fn content_matches(file: File, download: &McpExternalArchiveDownloadV1) -> bool {
    let mut reader = file.take(download.size.saturating_add(1));
    let mut buffer = vec![0_u8; CHUNK_BYTES];
    let mut digest = Sha256::new();
    let mut size: u64 = 0;
    loop {
        let read = match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) if error.kind() == ErrorKind::Interrupted => continue,
            Err(_) => return false,
        };
        size += read as u64;
        if size > download.size {
            return false;
        }
        digest.update(&buffer[..read]);
    }
    size == download.size && hex::encode(digest.finalize()) == download.sha256
}

#[cfg(unix)]
fn open_verified(path: &Path, size: u64) -> Option<File> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

    let path_metadata = std::fs::symlink_metadata(path).ok()?;
    // Never open a FIFO or device: the open itself could block a worker.
    if !path_metadata.file_type().is_file() {
        return None;
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .ok()?;
    let metadata = file.metadata().ok()?;
    let verified = metadata.file_type().is_file()
        && path_metadata.dev() == metadata.dev()
        && path_metadata.ino() == metadata.ino()
        && metadata.nlink() == 1
        && metadata.len() == size
        && metadata.mode() & 0o222 == 0;
    verified.then_some(file)
}

#[cfg(windows)]
fn open_verified(path: &Path, size: u64) -> Option<File> {
    use guard_runtime_windows_process::{handle_file_id, is_single_link_handle, regular_file_id};

    // The leaf is not followed: a link at the path is never a regular file.
    let (identity, _links) = regular_file_id(path, false).ok()?;
    let file = File::open(path).ok()?;
    let metadata = file.metadata().ok()?;
    let verified = metadata.file_type().is_file()
        && handle_file_id(&file).ok()? == identity
        && is_single_link_handle(&file).ok()?
        && metadata.len() == size
        && metadata.permissions().readonly();
    verified.then_some(file)
}
