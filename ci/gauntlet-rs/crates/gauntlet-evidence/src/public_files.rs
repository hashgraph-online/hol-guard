//! Bounded regular-file reads below a caller-selected no-symlink public root.

use crate::io::open_absolute_directory;
use crate::{EvidenceError, Result};
use gauntlet_contracts::canonical_relative_asset_path;
use rustix::fs::{openat, Mode, OFlags};
use sha2::{Digest, Sha256};
use std::fs::{File, Metadata};
use std::io::Read;
use std::os::fd::OwnedFd;
use std::os::unix::fs::MetadataExt;
use std::path::Path;

const MAX_PUBLIC_FILE_BYTES: u64 = 2 * 1024 * 1024 * 1024;

pub(crate) struct PublicRootReader {
    root: OwnedFd,
}

fn unchanged(before: &Metadata, after: &Metadata) -> bool {
    before.dev() == after.dev()
        && before.ino() == after.ino()
        && before.mode() == after.mode()
        && before.uid() == after.uid()
        && before.gid() == after.gid()
        && before.len() == after.len()
        && before.mtime() == after.mtime()
        && before.mtime_nsec() == after.mtime_nsec()
        && before.ctime() == after.ctime()
        && before.ctime_nsec() == after.ctime_nsec()
}

impl PublicRootReader {
    pub(crate) fn open(root: &Path) -> Result<Self> {
        Ok(Self {
            root: open_absolute_directory(root)?,
        })
    }

    fn open_regular(&self, path: &str) -> Result<(File, Metadata)> {
        if !canonical_relative_asset_path(path) {
            return Err(EvidenceError::Invalid("noncanonical public asset path"));
        }
        let mut parts = path.split('/').peekable();
        let mut parent = openat(
            &self.root,
            ".",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(|error| EvidenceError::Io(error.to_string()))?;
        while let Some(part) = parts.next() {
            if parts.peek().is_none() {
                let descriptor = openat(
                    &parent,
                    part,
                    OFlags::RDONLY | OFlags::NOFOLLOW | OFlags::NONBLOCK | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .map_err(|error| EvidenceError::Io(error.to_string()))?;
                let file = File::from(descriptor);
                let metadata = file
                    .metadata()
                    .map_err(|error| EvidenceError::Io(error.to_string()))?;
                if !metadata.is_file() || metadata.len() > MAX_PUBLIC_FILE_BYTES {
                    return Err(EvidenceError::Invalid(
                        "nonregular or oversized public file",
                    ));
                }
                return Ok((file, metadata));
            }
            parent = openat(
                &parent,
                part,
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::NOFOLLOW | OFlags::CLOEXEC,
                Mode::empty(),
            )
            .map_err(|error| EvidenceError::Io(error.to_string()))?;
        }
        Err(EvidenceError::Invalid("empty public asset path"))
    }

    pub(crate) fn read_file(&self, path: &str, limit: usize) -> Result<Vec<u8>> {
        let (mut file, before) = self.open_regular(path)?;
        if before.len() > limit as u64 {
            return Err(EvidenceError::Invalid("public file exceeds byte bound"));
        }
        let mut raw = Vec::with_capacity(before.len() as usize);
        file.by_ref()
            .take((limit + 1) as u64)
            .read_to_end(&mut raw)
            .map_err(|error| EvidenceError::Io(error.to_string()))?;
        let after = file
            .metadata()
            .map_err(|error| EvidenceError::Io(error.to_string()))?;
        if raw.len() > limit || raw.len() as u64 != before.len() || !unchanged(&before, &after) {
            return Err(EvidenceError::Invalid("public file changed while reading"));
        }
        Ok(raw)
    }

    pub(crate) fn file_digest(&self, path: &str, require_execute: bool) -> Result<String> {
        let (mut file, before) = self.open_regular(path)?;
        if require_execute && before.mode() & 0o111 == 0 {
            return Err(EvidenceError::Invalid(
                "pinned executable has no execute bit",
            ));
        }
        let mut hasher = Sha256::new();
        let mut total = 0_u64;
        let mut buffer = [0_u8; 1024 * 1024];
        loop {
            let count = file
                .read(&mut buffer)
                .map_err(|error| EvidenceError::Io(error.to_string()))?;
            if count == 0 {
                break;
            }
            total = total
                .checked_add(count as u64)
                .ok_or(EvidenceError::Invalid("public file byte count overflow"))?;
            if total > MAX_PUBLIC_FILE_BYTES {
                return Err(EvidenceError::Invalid("public file exceeds two GiB"));
            }
            hasher.update(&buffer[..count]);
        }
        let after = file
            .metadata()
            .map_err(|error| EvidenceError::Io(error.to_string()))?;
        if total != before.len() || !unchanged(&before, &after) {
            return Err(EvidenceError::Invalid("public file changed while hashing"));
        }
        Ok(format!("{:x}", hasher.finalize()))
    }
}
