//! The private request snapshot a routed call hands to the sink.
//!
//! The snapshot lives in an owner-only directory under the temporary
//! directory, named with the prefix the sink accepts, as `request.json`
//! with mode 0600. The sink checks those modes, the owner and the digest the
//! rewritten command pins before it reads the call, and removes the
//! snapshot once it has. A snapshot whose call never ran is reclaimed after
//! a day, as the daemon reclaims its own.

use super::{first, routed_response, HookDirectDefer, Routed, SinkTarget, Snapshot};
use nix::fcntl::AtFlags;
use nix::sys::stat::fstatat;
use nix::unistd::{getuid, unlinkat, UnlinkatFlags};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::fs::{DirBuilder, OpenOptions};
use std::io::Write;
use std::os::fd::AsFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) const REQUEST_SCHEMA: &str = "guard-contained-test-request.v1";
pub(crate) const REQUEST_DIRECTORY_PREFIX: &str = "hol-guard-contained-test-";
pub(crate) const REQUEST_FILE_NAME: &str = "request.json";
pub(crate) const MAX_REQUEST_BYTES: usize = 1_048_576;
const STALE_AFTER_SECONDS: i64 = 86_400;
const MAX_SCANNED_ENTRIES: usize = 4096;
const NAME_ATTEMPTS: usize = 16;
const NAME_CHARACTERS: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789_";

/// Write the snapshot of the call under `temp` and return the response that
/// runs the sink on it: the runtime's own sink at `native` when given, else
/// the daemon's.
pub(super) fn write_and_route(
    temp: &Path,
    payload: &Map<String, Value>,
    original: &Map<String, Value>,
    target: &SinkTarget<'_>,
    native: Option<&str>,
) -> Result<Option<Routed>, HookDirectDefer> {
    let failed = HookDirectDefer::ContainedRouteFailed;
    // The binding is only as fresh as its last publish; a launcher removed
    // since then leaves the call to the daemon, which resolves it again.
    if native.is_none() && !Path::new(&target.command[0]).is_file() {
        return Err(failed);
    }
    let workspace = std::fs::canonicalize(target.workspace).map_err(|_| failed)?;
    if !workspace.is_dir() {
        return Err(failed);
    }
    let workspace = workspace.to_str().ok_or(failed)?.to_owned();
    let serialized = serde_json::to_vec(&json!({
        "schema": REQUEST_SCHEMA,
        "workspace": workspace,
        "payload": {
            "hook_event_name": "PreToolUse",
            "tool_name": "bash",
            "tool_input": original,
            "cwd": workspace,
            "session_id": first(payload, &["session_id", "sessionId"]),
            "tool_call_id": first(payload, &["tool_call_id", "toolCallId", "tool_use_id"]),
        },
    }))
    .map_err(|_| failed)?;
    if serialized.len() > MAX_REQUEST_BYTES {
        return Ok(None);
    }
    cleanup_stale_requests(temp);
    let directory = private_directory(temp).ok_or(failed)?;
    let request = directory.join(REQUEST_FILE_NAME);
    let request_text = match request.to_str() {
        Some(text) if write_request(&request, &serialized).is_some() => text.to_owned(),
        _ => {
            let _ = std::fs::remove_file(&request);
            let _ = std::fs::remove_dir(&directory);
            return Err(failed);
        }
    };
    let digest = hex::encode(Sha256::digest(&serialized));
    let mut command = match native {
        Some(executable) => vec![
            executable.to_owned(),
            crate::contained_workspace_sink::SINK_COMMAND.to_owned(),
        ],
        None => {
            let mut command = target.command.to_vec();
            command.extend(["guard", "execute-contained-test"].map(str::to_owned));
            command
        }
    };
    command.extend(
        [
            "--harness",
            target.harness,
            "--guard-home",
            target.guard_home,
            "--workspace",
            workspace.as_str(),
            "--request-file",
            request_text.as_str(),
            "--request-sha256",
            digest.as_str(),
            "--home",
            target.home_dir,
        ]
        .map(str::to_owned),
    );
    Ok(Some((
        routed_response(original, &command),
        Snapshot::new(request),
    )))
}

/// Write `serialized` as a fresh private request snapshot under `temp`,
/// reclaiming stale ones first: the request path, or `None` with nothing
/// left behind.
pub(crate) fn write_snapshot(temp: &Path, serialized: &[u8]) -> Option<PathBuf> {
    cleanup_stale_requests(temp);
    let directory = private_directory(temp)?;
    let request = directory.join(REQUEST_FILE_NAME);
    if write_request(&request, serialized).is_some() {
        return Some(request);
    }
    let _ = std::fs::remove_file(&request);
    let _ = std::fs::remove_dir(&directory);
    None
}

/// A new owner-only directory under `temp`, named as `mkdtemp` names one.
fn private_directory(temp: &Path) -> Option<PathBuf> {
    for _ in 0..NAME_ATTEMPTS {
        let mut random = [0_u8; 8];
        getrandom::fill(&mut random).ok()?;
        let suffix: String = random
            .iter()
            .map(|byte| char::from(NAME_CHARACTERS[usize::from(*byte) % NAME_CHARACTERS.len()]))
            .collect();
        let path = temp.join(format!("{REQUEST_DIRECTORY_PREFIX}{suffix}"));
        match DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => return Some(path),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(_) => return None,
        }
    }
    None
}

fn write_request(path: &Path, serialized: &[u8]) -> Option<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .ok()?;
    file.write_all(serialized).ok()?;
    file.sync_all().ok()
}

/// Reclaim abandoned snapshots after a full day, never following a link.
pub(super) fn cleanup_stale_requests(temp: &Path) {
    let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        return;
    };
    let Ok(now) = i64::try_from(now.as_secs()) else {
        return;
    };
    let cutoff = now - STALE_AFTER_SECONDS;
    let Ok(entries) = std::fs::read_dir(temp) else {
        return;
    };
    let uid = getuid().as_raw();
    for entry in entries.take(MAX_SCANNED_ENTRIES).flatten() {
        let named = entry
            .file_name()
            .to_str()
            .is_some_and(|name| name.starts_with(REQUEST_DIRECTORY_PREFIX));
        if named {
            let _ = reclaim(&entry.path(), uid, cutoff);
        }
    }
}

fn reclaim(path: &Path, uid: u32, cutoff: i64) -> Option<()> {
    let directory = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)
        .ok()?;
    let parent = directory.metadata().ok()?;
    if parent.uid() != uid || parent.mode() & 0o7777 != 0o700 || parent.mtime() > cutoff {
        return None;
    }
    let request = fstatat(
        directory.as_fd(),
        REQUEST_FILE_NAME,
        AtFlags::AT_SYMLINK_NOFOLLOW,
    )
    .ok()?;
    let mode = request.st_mode as u64;
    if mode & libc::S_IFMT as u64 != libc::S_IFREG as u64
        || request.st_uid != uid
        || mode & 0o7777 != 0o600
        || request.st_nlink != 1
        || request.st_mtime > cutoff
    {
        return None;
    }
    unlinkat(
        directory.as_fd(),
        REQUEST_FILE_NAME,
        UnlinkatFlags::NoRemoveDir,
    )
    .ok()?;
    drop(directory);
    std::fs::remove_dir(path).ok()
}
