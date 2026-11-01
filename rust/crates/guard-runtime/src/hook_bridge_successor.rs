//! A hook bridge left behind by an update hands its hook to the runtime the
//! home's resident runs now.
//!
//! A harness reads its hook commands when a session starts, and Cursor's
//! agent keeps that list for the life of the process. A session that
//! outlives a Guard update therefore keeps launching the durable copy its
//! hooks named at start, while the resident restarts on the new runtime. The
//! resident answers only a bridge that runs its own runtime, so every hook
//! from that session missed it and went to the daemon.
//!
//! When this bridge is such a copy, and the live resident runs a copy
//! published after it in the same owner-only directory, this bridge runs
//! that copy's bridge on the same hook and answers what it answers. The
//! newer copy is the runtime the harness's hooks name today, so the hook is
//! decided exactly as a fresh session would have it decided. A bridge that
//! was handed a hook never hands it on.

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime};

use crate::hook_env_stamp::HOOK_HANDED_OFF_ENV;
use crate::resident_process_identity::durable_digest_for;
use crate::resident_state::{discover_same_executable_states, validate_process_start_marker};

const POLL_INTERVAL: Duration = Duration::from_millis(1);
/// A hook answer is a few kilobytes; nothing past this is read.
const MAX_OUTPUT_BYTES: u64 = 1 << 20;

/// What the successor bridge did with the hook.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum HandOff {
    /// Its stdout and exit code.
    Answered(Vec<u8>, i32),
    /// It ran but gave no answer before the deadline, or was killed.
    Failed,
}

/// The newer durable copy whose bridge should answer a hook this bridge
/// could not take to a resident, or `None` to keep the hook here.
pub(crate) fn successor(state_base: &Path) -> Option<PathBuf> {
    if std::env::var_os(HOOK_HANDED_OFF_ENV).is_some() {
        return None;
    }
    let executable = std::env::current_exe().and_then(fs::canonicalize).ok()?;
    let states = discover_same_executable_states(state_base).ok()?;
    // One live resident serves a home.
    let (_, live_digest, _) = states.into_iter().find(|(_, _, state)| {
        validate_process_start_marker(state.process_id, &state.process_start_marker).is_ok()
    })?;
    successor_copy(&executable, state_base, &live_digest)
}

/// The copy published as `live_digest` beside `executable`, when
/// `executable` is itself a durable copy under `state_base`, the two
/// differ, both are owner-only copies the publisher would trust, and the
/// live one was published after this one.
pub(crate) fn successor_copy(
    executable: &Path,
    state_base: &Path,
    live_digest: &str,
) -> Option<PathBuf> {
    let own_digest = durable_digest_for(executable, state_base)?;
    if live_digest.len() != 64
        || !live_digest.bytes().all(|byte| byte.is_ascii_hexdigit())
        || live_digest.eq_ignore_ascii_case(&own_digest)
    {
        return None;
    }
    let base = fs::canonicalize(state_base).ok()?;
    let candidate = base
        .join(live_digest.to_ascii_lowercase())
        .join(executable.file_name()?);
    let own_published = published_copy(executable)?;
    (published_copy(&candidate)? > own_published).then_some(candidate)
}

/// When an owner-only durable copy was published, or `None` for anything
/// the durable-copy publisher would not trust.
fn published_copy(file: &Path) -> Option<SystemTime> {
    let owner = nix::unistd::getuid().as_raw();
    let directory = fs::symlink_metadata(file.parent()?).ok()?;
    if !directory.is_dir()
        || directory.uid() != owner
        || directory.permissions().mode() & 0o022 != 0
    {
        return None;
    }
    let metadata = fs::symlink_metadata(file).ok()?;
    let mode = metadata.permissions().mode();
    if !metadata.is_file() || metadata.uid() != owner || mode & 0o022 != 0 || mode & 0o100 == 0 {
        return None;
    }
    metadata.modified().ok()
}

/// Run `successor` with `arguments`, `input` on its stdin, and wait for its
/// answer until `deadline`. `None` means it never started, so the hook is
/// still this bridge's to answer.
pub(crate) fn hand_off(
    successor: &Path,
    arguments: &[String],
    input: &[u8],
    deadline: Instant,
) -> Option<HandOff> {
    if Instant::now() >= deadline {
        return None;
    }
    let mut child = Command::new(successor)
        .args(arguments)
        .env(HOOK_HANDED_OFF_ENV, "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .ok()?;
    let (Some(mut stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        let _ = child.kill();
        let _ = child.wait();
        return Some(HandOff::Failed);
    };
    let input = input.to_vec();
    // The successor may answer before it reads everything; a closed pipe
    // then ends the write and its answer still counts.
    std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let (sender, receiver) = mpsc::channel();
    std::thread::spawn(move || {
        let mut output = Vec::new();
        let read = stdout.take(MAX_OUTPUT_BYTES).read_to_end(&mut output);
        let _ = sender.send(read.map(|_| output));
    });
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if Instant::now() < deadline => std::thread::sleep(POLL_INTERVAL),
            _ => {
                let _ = child.kill();
                let _ = child.wait();
                return Some(HandOff::Failed);
            }
        }
    };
    // Anything it left running still holds the pipe; stop reading at the
    // deadline rather than wait for it.
    let wait = deadline.saturating_duration_since(Instant::now());
    match (status.code(), receiver.recv_timeout(wait)) {
        (Some(code), Ok(Ok(output))) => Some(HandOff::Answered(output, code)),
        _ => Some(HandOff::Failed),
    }
}

#[cfg(test)]
#[path = "hook_bridge_successor_tests.rs"]
mod tests;
