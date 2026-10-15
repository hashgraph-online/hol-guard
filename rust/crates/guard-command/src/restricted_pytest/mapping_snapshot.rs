//! Owned, private descriptor handoff for indexes larger than an IPC frame.
use super::*;
use nix::fcntl::{openat, OFlag};
use nix::sys::stat::Mode;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::OpenOptions;
use std::io::{Read, Write};
use std::os::unix::fs::OpenOptionsExt;
use std::time::Instant;

fn check(deadline: Instant) -> Result<(), &'static str> {
    if Instant::now() >= deadline {
        Err("Linux executable mapping inspection deadline exceeded.")
    } else {
        Ok(())
    }
}

fn directory(input: &Value) -> Result<fs::File, &'static str> {
    let error = "Invalid executable mapping snapshot.";
    if input.as_object().is_none_or(|v| v.len() != 3) {
        return Err(error);
    }
    let path = Path::new(input["mapping_snapshot"].as_str().ok_or(error)?);
    let parent = path.parent().ok_or(error)?;
    if path.file_name() != Some(OsStr::new("mapping-index.json"))
        || !parent.is_absolute()
        || !parent
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|p| p.starts_with("hol-guard-mapping-"))
        || parent.canonicalize().map_err(|_| error)? != parent
    {
        return Err(error);
    }
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)
        .map_err(|_| error)?;
    let metadata = directory.metadata().map_err(|_| error)?;
    if metadata.uid() != nix::unistd::getuid().as_raw() || metadata.mode() & 0o077 != 0 {
        return Err(error);
    }
    Ok(directory)
}

pub(super) fn read(input: &Value, deadline: Instant) -> Result<Value, &'static str> {
    let error = "Invalid executable mapping snapshot.";
    check(deadline)?;
    let directory = directory(input)?;
    let length = input["decoded_bytes"]
        .as_u64()
        .filter(|v| *v <= 256 * 1024 * 1024)
        .ok_or(error)?;
    let digest = input["sha256"]
        .as_str()
        .filter(|v| {
            v.len() == 64
                && v.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        .ok_or(error)?;
    let descriptor = openat(
        &directory,
        "mapping-index.json",
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
        Mode::empty(),
    )
    .map_err(|_| error)?;
    let mut file = fs::File::from(descriptor);
    let before = file.metadata().map_err(|_| error)?;
    if !before.is_file()
        || before.uid() != nix::unistd::getuid().as_raw()
        || before.mode() & 0o077 != 0
        || before.nlink() != 1
        || before.len() != length
    {
        return Err(error);
    }
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 1024 * 1024];
    loop {
        check(deadline)?;
        let read = file.read(&mut chunk).map_err(|_| error)?;
        if read == 0 {
            break;
        }
        let room = (length as usize)
            .saturating_add(1)
            .saturating_sub(bytes.len());
        if room == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..read.min(room)]);
        if bytes.len() > length as usize {
            break;
        }
    }
    check(deadline)?;
    let after = file.metadata().map_err(|_| error)?;
    if bytes.len() as u64 != length
        || before.dev() != after.dev()
        || before.ino() != after.ino()
        || before.len() != after.len()
        || before.mtime() != after.mtime()
        || before.mtime_nsec() != after.mtime_nsec()
        || format!("{:x}", Sha256::digest(&bytes)) != digest
    {
        return Err(error);
    }
    check(deadline)?;
    let parsed = serde_json::from_slice(&bytes).map_err(|_| error)?;
    check(deadline)?;
    Ok(parsed)
}

pub(super) fn write(
    input: &Value,
    value: &Value,
    deadline: Instant,
) -> Result<Value, &'static str> {
    let error = "Invalid executable mapping result snapshot.";
    check(deadline)?;
    let directory = directory(input)?;
    let bytes = serde_json::to_vec(value).map_err(|_| error)?;
    check(deadline)?;
    if bytes.len() > 32 * 1024 * 1024 {
        return Err("Executable mapping result exceeds its wire budget.");
    }
    let descriptor = openat(
        &directory,
        "mapping-result.json",
        OFlag::O_WRONLY | OFlag::O_CREAT | OFlag::O_EXCL | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
        Mode::from_bits_truncate(0o600),
    )
    .map_err(|_| error)?;
    let mut file = fs::File::from(descriptor);
    for chunk in bytes.chunks(1024 * 1024) {
        check(deadline)?;
        file.write_all(chunk).map_err(|_| error)?;
    }
    check(deadline)?;
    Ok(
        serde_json::json!({"decoded_bytes":bytes.len(),"sha256":format!("{:x}",Sha256::digest(&bytes))}),
    )
}
