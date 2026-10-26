//! Stable no-follow copies with exact original identity and content digest.
use super::mapping_records::Record;
use super::plan::Result;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::path::Path;

pub(super) fn identity(metadata: &std::fs::Metadata) -> Result<[u64; 5]> {
    let nanos = metadata.mtime() as i128 * 1_000_000_000 + metadata.mtime_nsec() as i128;
    Ok([
        metadata.dev(),
        metadata.ino(),
        metadata.len(),
        u64::try_from(nanos).map_err(|_| "Invalid executable mapping identity.")?,
        metadata.mode() as u64,
    ])
}

pub(super) fn seal(record: &Record, destination: &Path) -> Result<File> {
    let mut source = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(&record.path)
        .map_err(|_| "Executable mapping changed before copying.")?;
    if identity(
        &source
            .metadata()
            .map_err(|_| "Executable mapping changed before copying.")?,
    )? != record.identity
    {
        return Err("Executable mapping changed before copying.");
    }
    let mut copy = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(destination)
        .map_err(|_| "Executable mapping copy could not be created.")?;
    let mut digest = Sha256::new();
    let mut remaining = record.identity[2];
    let mut buffer = vec![0u8; 1024 * 1024];
    while remaining > 0 {
        let limit = remaining.min(buffer.len() as u64) as usize;
        let count = source
            .read(&mut buffer[..limit])
            .map_err(|_| "Executable mapping copy failed.")?;
        if count == 0 {
            return Err("Executable mapping was truncated.");
        }
        digest.update(&buffer[..count]);
        copy.write_all(&buffer[..count])
            .map_err(|_| "Executable mapping copy did not progress.")?;
        remaining -= count as u64;
    }
    let mut extra = [0u8; 1];
    if source
        .read(&mut extra)
        .map_err(|_| "Executable mapping content changed.")?
        != 0
        || identity(
            &source
                .metadata()
                .map_err(|_| "Executable mapping content changed.")?,
        )? != record.identity
        || format!("{:x}", digest.finalize()) != record.digest
    {
        return Err("Executable mapping content changed.");
    }
    copy.set_permissions(std::fs::Permissions::from_mode(0o500))
        .map_err(|_| "Executable mapping could not be sealed.")?;
    Ok(copy)
}
