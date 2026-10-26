//! Bounded descriptor-bound index output keeps the resident reply small.
use super::BoundaryResult as Result;
use nix::fcntl::{openat, OFlag};
use nix::sys::stat::Mode;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;
use std::time::Instant;

pub(super) fn check(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        Err("Linux execution snapshot exceeds its time budget.")
    } else {
        Ok(())
    }
}

pub(super) fn write_bytes(file: &mut File, bytes: &[u8], deadline: Instant) -> Result<()> {
    for chunk in bytes.chunks(1024 * 1024) {
        check(deadline)?;
        file.write_all(chunk)
            .map_err(|_| "Linux execution snapshot could not be written.")?;
        check(deadline)?;
    }
    check(deadline)
}

pub(super) fn write(path: &Path, value: &Value, deadline: Instant) -> Result<Value> {
    check(deadline)?;
    let message = "Linux workspace index transport is unavailable.";
    let parent = path.parent().ok_or(message)?;
    if !parent.is_absolute()
        || path.file_name().and_then(|v| v.to_str()) != Some("linux-index.json")
        || !parent
            .file_name()
            .and_then(|v| v.to_str())
            .is_some_and(|v| v.starts_with("hol-guard-linux-index-"))
        || parent.canonicalize().map_err(|_| message)? != parent
    {
        return Err(message);
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)
        .map_err(|_| message)?;
    let metadata = directory.metadata().map_err(|_| message)?;
    if metadata.uid() != nix::unistd::getuid().as_raw() || metadata.mode() & 0o077 != 0 {
        return Err(message);
    }
    let bytes = serde_json::to_vec(value).map_err(|_| message)?;
    check(deadline)?;
    if bytes.len() > 64 * 1024 * 1024 {
        return Err("Linux workspace index exceeds its wire budget.");
    }
    let digest = format!("{:x}", Sha256::digest(&bytes));
    check(deadline)?;
    let descriptor = openat(
        &directory,
        "linux-index.json",
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|_| message)?;
    let mut file = File::from(descriptor);
    write_bytes(&mut file, &bytes, deadline)?;
    Ok(json!({"decoded_bytes":bytes.len(),"sha256":digest}))
}
