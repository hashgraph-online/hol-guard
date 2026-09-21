//! Held-descriptor, bounded package and invocation identity checks.
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::Path;

use super::{Failure, Result};

fn stamp(value: &fs::Metadata) -> (u64, u64, u64, i64, i64, u32) {
    (
        value.dev(),
        value.ino(),
        value.len(),
        value.mtime(),
        value.mtime_nsec(),
        value.mode(),
    )
}

fn open_bound_file(path: &Path, maximum: u64, private: bool) -> Result<(fs::File, fs::Metadata)> {
    let before = fs::symlink_metadata(path).map_err(Failure::io)?;
    let parent = fs::symlink_metadata(
        path.parent()
            .ok_or_else(|| Failure::identity("claude_pilot_path_invalid"))?,
    )
    .map_err(Failure::io)?;
    let owner = nix::unistd::getuid().as_raw();
    let mask = if private { 0o077 } else { 0o022 };
    if !before.is_file()
        || !parent.is_dir()
        || before.len() > maximum
        || before.mode() & mask != 0
        || parent.mode() & mask != 0
        || (before.uid() != owner && (private || before.uid() != 0))
        || (parent.uid() != owner && (private || parent.uid() != 0))
    {
        return Err(Failure::identity("claude_pilot_file_permissions_or_shape"));
    }
    if path.canonicalize().map_err(Failure::io)? != path {
        return Err(Failure::identity("claude_pilot_path_has_symlink"));
    }
    let file = open_unchanged(path, &before)?;
    Ok((file, before))
}

fn open_unchanged(path: &Path, before: &fs::Metadata) -> Result<fs::File> {
    // A regular file may be replaced by a FIFO after metadata validation.
    // Nonblocking open lets held-descriptor checks reject it without waiting
    // for a writer; this does not change ordinary regular-file reads.
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(Failure::io)?;
    unchanged(&file, path, before)?;
    Ok(file)
}

fn unchanged(file: &fs::File, path: &Path, before: &fs::Metadata) -> Result<()> {
    if stamp(&file.metadata().map_err(Failure::io)?) != stamp(before)
        || stamp(&fs::symlink_metadata(path).map_err(Failure::io)?) != stamp(before)
    {
        return Err(Failure::identity("claude_pilot_file_changed"));
    }
    Ok(())
}

pub(super) fn read_file(path: &Path, maximum: u64, private: bool) -> Result<Vec<u8>> {
    let (mut file, before) = open_bound_file(path, maximum, private)?;
    let mut bytes = Vec::new();
    (&mut file)
        .take(maximum + 1)
        .read_to_end(&mut bytes)
        .map_err(Failure::io)?;
    if bytes.len() as u64 > maximum {
        return Err(Failure::identity("claude_pilot_file_changed"));
    }
    unchanged(&file, path, &before)?;
    Ok(bytes)
}

fn file_digest(path: &Path, maximum: u64) -> Result<(String, fs::Metadata)> {
    let (mut file, before) = open_bound_file(path, maximum, false)?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 65_536];
    let mut count = 0;
    loop {
        let read = file.read(&mut buffer).map_err(Failure::io)?;
        if read == 0 {
            break;
        }
        count += read as u64;
        if count > maximum {
            return Err(Failure::identity("claude_pilot_file_changed"));
        }
        hash.update(&buffer[..read]);
    }
    if count != before.len() {
        return Err(Failure::identity("claude_pilot_file_changed"));
    }
    unchanged(&file, path, &before)?;
    Ok((hex::encode(hash.finalize()), before))
}

pub(super) fn private_text(path: &Path, maximum: u64) -> Result<String> {
    String::from_utf8(read_file(path, maximum, true)?)
        .map_err(|_| Failure::identity("claude_pilot_private_text_invalid"))
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str> {
    value
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| Failure::identity("claude_pilot_record_invalid"))
}

pub(super) fn verify_file(binding: &Value) -> Result<()> {
    let invocation = Path::new(text(binding, "path")?);
    let resolved = invocation.canonicalize().map_err(Failure::io)?;
    if resolved != Path::new(text(binding, "resolved")?) || !invocation.is_absolute() {
        return Err(Failure::identity("claude_pilot_invocation_changed"));
    }
    let link = fs::symlink_metadata(invocation).map_err(Failure::io)?;
    if binding.get("invocation").and_then(Value::as_bool) != Some(true)
        && link.file_type().is_symlink()
    {
        return Err(Failure::identity("claude_pilot_file_symlink"));
    }
    let (digest, metadata) = file_digest(&resolved, 512 * 1024 * 1024)?;
    let nanos = |value: &fs::Metadata| {
        i128::from(value.mtime()) * 1_000_000_000 + i128::from(value.mtime_nsec())
    };
    if binding.get("size").and_then(Value::as_u64) != Some(metadata.len())
        || binding.get("device").and_then(Value::as_u64) != Some(metadata.dev())
        || binding.get("inode").and_then(Value::as_u64) != Some(metadata.ino())
        || binding
            .get("mtime_ns")
            .and_then(Value::as_i64)
            .map(i128::from)
            != Some(nanos(&metadata))
        || binding.get("link_device").and_then(Value::as_u64) != Some(link.dev())
        || binding.get("link_inode").and_then(Value::as_u64) != Some(link.ino())
        || binding
            .get("link_mtime_ns")
            .and_then(Value::as_i64)
            .map(i128::from)
            != Some(nanos(&link))
        || text(binding, "sha256")? != digest
    {
        return Err(Failure::identity("claude_pilot_file_identity_changed"));
    }
    if stamp(&fs::symlink_metadata(invocation).map_err(Failure::io)?) != stamp(&link) {
        return Err(Failure::identity("claude_pilot_invocation_changed"));
    }
    Ok(())
}

#[cfg(test)]
#[path = "claude_launcher_pilot_files_tests.rs"]
mod tests;
