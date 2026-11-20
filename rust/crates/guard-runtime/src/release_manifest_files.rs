//! The no-follow reads release-manifest verification hashes a runtime through.
//!
//! Each file is opened without following a final link (or, on Windows, a
//! reparse point), bounded before and during the read, and refused when its
//! identity or size changes while it is read.

use std::fs::{File, Metadata};
use std::io::Read;
use std::path::Path;

use sha2::{Digest, Sha256};

use super::Invalid;

const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const HASH_CHUNK_BYTES: usize = 1024 * 1024;
#[cfg(windows)]
const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x400;

#[cfg(windows)]
pub(super) fn is_reparse_point(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
pub(super) fn is_reparse_point(_metadata: &Metadata) -> bool {
    false
}

fn open_readonly_no_follow(path: &Path) -> std::io::Result<File> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::{MetadataExt, OpenOptionsExt};
        const FILE_SHARE_ALL: u32 = 0x7;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        const FILE_FLAG_SEQUENTIAL_SCAN: u32 = 0x0800_0000;
        let file = std::fs::OpenOptions::new()
            .read(true)
            .share_mode(FILE_SHARE_ALL)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN)
            .open(path)?;
        if file.metadata()?.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(std::io::Error::other("runtime entry is a reparse point"));
        }
        Ok(file)
    }
}

/// The fields that change when a file is replaced or rewritten.
#[cfg(unix)]
fn stable_fields(metadata: &Metadata) -> (u64, u64, u64, i64, i64, i64, i64) {
    use std::os::unix::fs::MetadataExt;
    (
        metadata.dev(),
        metadata.ino(),
        metadata.size(),
        metadata.mtime(),
        metadata.mtime_nsec(),
        metadata.ctime(),
        metadata.ctime_nsec(),
    )
}

#[cfg(windows)]
fn stable_fields(metadata: &Metadata) -> (u64, u64, u64) {
    use std::os::windows::fs::MetadataExt;
    (
        metadata.file_size(),
        metadata.last_write_time(),
        metadata.creation_time(),
    )
}

pub(super) enum HashFailure {
    TooLarge,
    Unreadable,
}

impl From<std::io::Error> for HashFailure {
    fn from(_: std::io::Error) -> Self {
        HashFailure::Unreadable
    }
}

/// Read at most `limit + 1` bytes through `file`, failing once past `limit`.
fn read_limited(
    file: &mut File,
    limit: u64,
    mut sink: impl FnMut(&[u8]),
) -> Result<u64, HashFailure> {
    let mut buffer = vec![0_u8; HASH_CHUNK_BYTES];
    let mut consumed = 0_u64;
    loop {
        let wanted = usize::try_from((limit - consumed.min(limit)) + 1)
            .unwrap_or(HASH_CHUNK_BYTES)
            .min(HASH_CHUNK_BYTES);
        let read = file.read(&mut buffer[..wanted])?;
        if read == 0 {
            return Ok(consumed);
        }
        consumed += read as u64;
        if consumed > limit {
            return Err(HashFailure::TooLarge);
        }
        sink(&buffer[..read]);
    }
}

pub(super) fn hash_regular_file(
    path: &Path,
    limit: u64,
) -> Result<(String, u64, Metadata), HashFailure> {
    let mut file = open_readonly_no_follow(path)?;
    let before = file.metadata()?;
    if !before.is_file() {
        return Err(HashFailure::Unreadable);
    }
    if before.len() > limit {
        return Err(HashFailure::TooLarge);
    }
    let mut digest = Sha256::new();
    let consumed = read_limited(&mut file, limit, |chunk| digest.update(chunk))?;
    let after = file.metadata()?;
    if consumed != before.len() || stable_fields(&before) != stable_fields(&after) {
        return Err(HashFailure::Unreadable);
    }
    Ok((hex::encode(digest.finalize()), consumed, before))
}

pub(super) fn read_bounded_regular_file(path: &Path) -> Result<(Vec<u8>, Metadata), Invalid> {
    let mut file = open_readonly_no_follow(path)?;
    let before = file.metadata()?;
    if !before.is_file() || before.len() > MAX_MANIFEST_BYTES {
        return Err(Invalid);
    }
    let mut bytes = Vec::new();
    let consumed = read_limited(&mut file, MAX_MANIFEST_BYTES, |chunk| {
        bytes.extend_from_slice(chunk);
    })
    .map_err(|_| Invalid)?;
    let after = file.metadata()?;
    if consumed != before.len() || stable_fields(&before) != stable_fields(&after) {
        return Err(Invalid);
    }
    Ok((bytes, before))
}
