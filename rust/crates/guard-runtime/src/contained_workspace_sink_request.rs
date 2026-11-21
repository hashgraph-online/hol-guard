//! The call snapshot the resident hands the sink: read once, checked, removed.

use std::fs::File;
use std::io::Read;
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

use nix::fcntl::{openat, OFlag};
use nix::sys::stat::Mode;
use sha2::{Digest, Sha256};

use crate::hook_direct::contained::request::{
    MAX_REQUEST_BYTES, REQUEST_DIRECTORY_PREFIX, REQUEST_FILE_NAME, REQUEST_SCHEMA,
};

use super::*;

/// Read, check and remove the snapshot the resident wrote: the call it holds.
pub(super) fn read_request(
    path: &Path,
    digest: &str,
    workspace: &Path,
) -> Outcome<Map<String, Value>> {
    let parent = path.parent().ok_or_else(Failure::unauthorized)?;
    let parent_named = parent
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with(REQUEST_DIRECTORY_PREFIX));
    let digest_valid = digest.len() == 64
        && digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte));
    if path.file_name().and_then(|name| name.to_str()) != Some(REQUEST_FILE_NAME)
        || !parent_named
        || !digest_valid
    {
        return Err(Failure::unauthorized());
    }
    let raw = read_private_request(parent).ok_or_else(Failure::unauthorized)?;
    let payload = decode_request(&raw, digest, workspace).ok_or_else(Failure::unauthorized)?;
    // A validated request is single-use.
    let _ = std::fs::remove_file(path);
    let _ = std::fs::remove_dir(parent);
    Ok(payload)
}

/// The bytes of `request.json` in the owner-only `directory`, read without
/// following a link at either level.
fn read_private_request(directory: &Path) -> Option<Vec<u8>> {
    let uid = nix::unistd::getuid().as_raw();
    let directory = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(directory)
        .ok()?;
    let status = directory.metadata().ok()?;
    if !status.is_dir() || status.mode() & 0o777 != 0o700 || status.uid() != uid {
        return None;
    }
    let descriptor = openat(
        &directory,
        REQUEST_FILE_NAME,
        OFlag::O_RDONLY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC | OFlag::O_NONBLOCK,
        Mode::empty(),
    )
    .ok()?;
    let file = File::from(descriptor);
    let status = file.metadata().ok()?;
    let limit = u64::try_from(MAX_REQUEST_BYTES).ok()?;
    if !status.is_file() || status.mode() & 0o777 != 0o600 || status.uid() != uid {
        return None;
    }
    if status.len() > limit {
        return None;
    }
    let mut raw = Vec::new();
    file.take(limit + 1).read_to_end(&mut raw).ok()?;
    (raw.len() <= MAX_REQUEST_BYTES).then_some(raw)
}

/// The call in a snapshot whose digest is `digest`, written for `workspace`.
pub(super) fn decode_request(
    raw: &[u8],
    digest: &str,
    workspace: &Path,
) -> Option<Map<String, Value>> {
    if hex::encode(Sha256::digest(raw)) != digest {
        return None;
    }
    let Value::Object(mut request) = crate::strict_json::parse(raw).ok()? else {
        return None;
    };
    let keys: Vec<&str> = request.keys().map(String::as_str).collect();
    let mut expected = ["payload", "schema", "workspace"];
    expected.sort_unstable();
    let mut sorted = keys.clone();
    sorted.sort_unstable();
    if sorted != expected || request.get("schema")?.as_str()? != REQUEST_SCHEMA {
        return None;
    }
    if !same_directory(request.get("workspace")?.as_str()?, workspace) {
        return None;
    }
    let Value::Object(payload) = request.remove("payload")? else {
        return None;
    };
    if let Some(cwd) = payload.get("cwd") {
        if !same_directory(cwd.as_str()?, workspace) {
            return None;
        }
    }
    let tool_input = payload.get("tool_input")?.as_object()?;
    if payload.get("hook_event_name")?.as_str()? != "PreToolUse"
        || payload.get("tool_name")?.as_str()? != "bash"
        || !tool_input.get("command")?.is_string()
    {
        return None;
    }
    Some(payload)
}

fn same_directory(text: &str, workspace: &Path) -> bool {
    std::fs::canonicalize(text).is_ok_and(|path| path == workspace)
}
