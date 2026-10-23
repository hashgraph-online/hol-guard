//! Inert verifier for a retained Python Git-object archive. It never extracts,
//! invokes Git, contacts a source host, or authorizes a build.

use crate::private_jobs::{child_directory, same_file, state_root};
use flate2::read::MultiGzDecoder;
use rustix::fs::{fstat, openat, statat, AtFlags, FileType, Mode, OFlags};
use rustix::process::geteuid;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;
use std::fs::File;
use std::io::{self, Read};
use std::path::Path;

const MAX_ARCHIVE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 512 * 1024 * 1024;
const MAX_TAR_BYTES: u64 = 640 * 1024 * 1024;
const MAX_ENTRIES: usize = 100_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SourceArchiveError {
    InvalidInput,
    UnsafeDirectory,
    UnsafeArchive,
    Changed,
    TooLarge,
    DigestMismatch,
    InvalidTar,
    Io,
}

impl fmt::Display for SourceArchiveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::InvalidInput => "invalid source archive pin or job ID",
            Self::UnsafeDirectory => "private source archive directory is unsafe",
            Self::UnsafeArchive => "private source archive file is unsafe",
            Self::Changed => "private source archive changed during read",
            Self::TooLarge => "source archive exceeds inventory bounds",
            Self::DigestMismatch => "source archive differs from outside SHA-256 pin",
            Self::InvalidTar => "source archive contains invalid Git-object tar data",
            Self::Io => "source archive I/O failed",
        })
    }
}

impl std::error::Error for SourceArchiveError {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceArchiveInventory {
    pub archive_sha256: String,
    pub compressed_bytes: u64,
    pub entries: usize,
    pub regular_files: usize,
    pub directories: usize,
    pub file_bytes: u64,
    pub execution_eligible: bool,
}

fn hex_pin(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn valid_member(path: &[u8], is_directory: bool) -> bool {
    let Some(tail) = path.strip_prefix(b"repository.git/") else {
        return false;
    };
    let tail = if is_directory {
        tail.strip_suffix(b"/").unwrap_or(tail)
    } else {
        tail
    };
    !tail.is_empty()
        && tail.split(|byte| *byte == b'/').all(|part| {
            !part.is_empty()
                && part != b"."
                && part != b".."
                && part
                    .iter()
                    .all(|byte| byte.is_ascii_graphic() && *byte != b'\\')
        })
}

struct BoundedReader<R> {
    inner: R,
    consumed: u64,
}

impl<R: Read> Read for BoundedReader<R> {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.consumed >= MAX_TAR_BYTES {
            let mut extra = [0u8; 1];
            return match self.inner.read(&mut extra)? {
                0 => Ok(0),
                _ => Err(io::Error::other("decompressed archive limit exceeded")),
            };
        }
        let available = (MAX_TAR_BYTES - self.consumed).min(buffer.len() as u64) as usize;
        let count = self.inner.read(&mut buffer[..available])?;
        self.consumed += count as u64;
        Ok(count)
    }
}

fn inventory(bytes: &[u8], sha256: &str) -> Result<SourceArchiveInventory, SourceArchiveError> {
    let decoder = MultiGzDecoder::new(bytes);
    let bounded = BoundedReader {
        inner: decoder,
        consumed: 0,
    };
    let mut archive = tar::Archive::new(bounded);
    let mut names = HashSet::new();
    let mut result = SourceArchiveInventory {
        archive_sha256: sha256.to_owned(),
        compressed_bytes: bytes.len() as u64,
        entries: 0,
        regular_files: 0,
        directories: 0,
        file_bytes: 0,
        execution_eligible: false,
    };
    for entry in archive
        .entries()
        .map_err(|_| SourceArchiveError::InvalidTar)?
    {
        let mut entry = entry.map_err(|_| SourceArchiveError::InvalidTar)?;
        result.entries += 1;
        if result.entries > MAX_ENTRIES {
            return Err(SourceArchiveError::TooLarge);
        }
        let kind = entry.header().entry_type();
        let is_directory = kind.is_dir();
        if !kind.is_file() && !is_directory {
            return Err(SourceArchiveError::InvalidTar);
        }
        let path = entry.path_bytes();
        if !valid_member(&path, is_directory) {
            return Err(SourceArchiveError::InvalidTar);
        }
        let name = path.strip_suffix(b"/").unwrap_or(&path);
        if !names.insert(name.to_vec()) {
            return Err(SourceArchiveError::InvalidTar);
        }
        if is_directory {
            if entry.size() != 0 {
                return Err(SourceArchiveError::InvalidTar);
            }
            result.directories += 1;
        } else {
            result.file_bytes = result
                .file_bytes
                .checked_add(entry.size())
                .ok_or(SourceArchiveError::TooLarge)?;
            if result.file_bytes > MAX_FILE_BYTES {
                return Err(SourceArchiveError::TooLarge);
            }
            let copied = io::copy(&mut entry, &mut io::sink())
                .map_err(|_| SourceArchiveError::InvalidTar)?;
            if copied != entry.size() {
                return Err(SourceArchiveError::InvalidTar);
            }
            result.regular_files += 1;
        }
    }
    // The tar iterator stops at its end marker. Drain the gzip decoder to
    // validate the trailer and reject nonzero data after that marker.
    let mut remainder = archive.into_inner();
    let mut buffer = [0u8; 8192];
    loop {
        let count = remainder
            .read(&mut buffer)
            .map_err(|_| SourceArchiveError::InvalidTar)?;
        if count == 0 {
            break;
        }
        if buffer[..count].iter().any(|byte| *byte != 0) {
            return Err(SourceArchiveError::InvalidTar);
        }
    }
    if result.regular_files == 0
        || !names.contains(b"repository.git/HEAD".as_slice())
        || !names.contains(b"repository.git/config".as_slice())
        || !names
            .iter()
            .any(|name| name.starts_with(b"repository.git/objects/"))
    {
        return Err(SourceArchiveError::InvalidTar);
    }
    Ok(result)
}

/// Verify the bytes and ordinary-member shape of an existing Python-produced
/// source archive against a caller-supplied outside SHA-256. The caller must
/// establish the pin's trust independently; this reader never grants execution.
pub(crate) fn verified_archive_bytes(
    state: &Path,
    job_id: &str,
    expected_sha256: &str,
) -> Result<(Vec<u8>, SourceArchiveInventory), SourceArchiveError> {
    if !hex_pin(job_id, 16) || !hex_pin(expected_sha256, 64) {
        return Err(SourceArchiveError::InvalidInput);
    }
    let owner = geteuid().as_raw();
    let root = state_root(state, owner).map_err(|_| SourceArchiveError::UnsafeDirectory)?;
    let private = child_directory(&root, "private", owner)
        .map_err(|_| SourceArchiveError::UnsafeDirectory)?;
    let builds = child_directory(&private, "local-builds", owner)
        .map_err(|_| SourceArchiveError::UnsafeDirectory)?;
    let job =
        child_directory(&builds, job_id, owner).map_err(|_| SourceArchiveError::UnsafeDirectory)?;
    let job_before = fstat(&job).map_err(|_| SourceArchiveError::Io)?;
    let descriptor = openat(
        &job,
        "source.tar.gz",
        OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| SourceArchiveError::Io)?;
    let before = fstat(&descriptor).map_err(|_| SourceArchiveError::Io)?;
    if FileType::from_raw_mode(before.st_mode) != FileType::RegularFile
        || before.st_uid != owner
        || before.st_mode & 0o777 != 0o600
        || before.st_nlink != 1
        || before.st_size <= 0
    {
        return Err(SourceArchiveError::UnsafeArchive);
    }
    if before.st_size as u64 > MAX_ARCHIVE_BYTES {
        return Err(SourceArchiveError::TooLarge);
    }
    let named_before = statat(&job, "source.tar.gz", AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| SourceArchiveError::Changed)?;
    if !same_file(&before, &named_before) {
        return Err(SourceArchiveError::Changed);
    }
    let mut file = File::from(descriptor);
    let mut bytes = Vec::with_capacity(before.st_size as usize);
    file.by_ref()
        .take(MAX_ARCHIVE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| SourceArchiveError::Io)?;
    if bytes.len() as u64 > MAX_ARCHIVE_BYTES {
        return Err(SourceArchiveError::TooLarge);
    }
    let after = fstat(&file).map_err(|_| SourceArchiveError::Io)?;
    let named_after = statat(&job, "source.tar.gz", AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| SourceArchiveError::Changed)?;
    let job_after = statat(&builds, job_id, AtFlags::SYMLINK_NOFOLLOW)
        .map_err(|_| SourceArchiveError::Changed)?;
    if bytes.len() as i64 != before.st_size
        || !same_file(&before, &after)
        || !same_file(&before, &named_after)
        || !same_file(&job_before, &job_after)
    {
        return Err(SourceArchiveError::Changed);
    }
    let actual_sha256 = format!("{:x}", Sha256::digest(&bytes));
    if actual_sha256 != expected_sha256 {
        return Err(SourceArchiveError::DigestMismatch);
    }
    let inventory = inventory(&bytes, &actual_sha256)?;
    Ok((bytes, inventory))
}

/// Verify the bytes and ordinary-member shape of an existing Python-produced
/// source archive against a caller-supplied outside SHA-256. The caller must
/// establish the pin's trust independently; this reader never grants execution.
pub fn verify_retained_source_archive(
    state: &Path,
    job_id: &str,
    expected_sha256: &str,
) -> Result<SourceArchiveInventory, SourceArchiveError> {
    verified_archive_bytes(state, job_id, expected_sha256).map(|(_, inventory)| inventory)
}
