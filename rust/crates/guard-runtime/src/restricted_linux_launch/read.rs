//! Descriptor-bound private plan read at the one namespace locator.
use super::{json, plan};
use nix::fcntl::{openat, OFlag};
use nix::sys::stat::Mode;
use plan::{Plan, Result};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

pub(super) fn load(digest: &str) -> Result<Plan> {
    plan::locator(digest)?;
    read_at(Path::new(plan::DIRECTORY), digest)
}

pub(super) fn read_at(directory: &Path, digest: &str) -> Result<Plan> {
    let parent = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory)
        .map_err(|_| "Unsafe Linux plan directory.")?;
    let metadata = parent
        .metadata()
        .map_err(|_| "Unsafe Linux plan directory.")?;
    let uid = nix::unistd::getuid().as_raw();
    if metadata.uid() != uid || metadata.mode() & 0o077 != 0 {
        return Err("Unsafe Linux plan directory.");
    }
    let descriptor = openat(
        &parent,
        plan::FILENAME,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| "Unsafe Linux plan file.")?;
    let file = File::from(descriptor);
    let metadata = file.metadata().map_err(|_| "Unsafe Linux plan file.")?;
    if !metadata.is_file()
        || metadata.uid() != uid
        || metadata.mode() & 0o077 != 0
        || metadata.nlink() != 1
        || metadata.len() > plan::MAX_BYTES
    {
        return Err("Unsafe Linux plan file.");
    }
    let mut bytes = Vec::new();
    file.take(plan::MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "Linux execution plan changed.")?;
    if bytes.len() as u64 > plan::MAX_BYTES || format!("{:x}", Sha256::digest(&bytes)) != digest {
        return Err("Linux execution plan changed.");
    }
    plan::parse(json::parse(&bytes)?)
}
