//! `durable-runtime-collapse --stdin`: let the frozen build's older durable
//! runtime copies under `<guard_home>/native-runtime` share the current one's
//! file instead of each holding a full executable.
//!
//! A frozen Guard writes `native-runtime/<sha256>/hol-guard-runtime` into
//! harness hook commands (`native_runtime_durable.py`), so every update leaves
//! one more full copy of the runtime behind. Nothing removed them, and a
//! long-lived install collects gigabytes of runtime executables.
//!
//! Deleting an older copy is not safe. A hook artifact Guard does not track,
//! or one whose repin failed, may still name it, and a hook command whose
//! program is missing fails to start, which most harnesses treat as a
//! non-blocking error: the tool call goes ahead unreviewed. So an older copy is
//! never removed. Its directory entry is replaced, atomically, by a hard link
//! to the current verified copy. Every pinned path still launches a Guard
//! runtime, the current one, and the disk holds a single runtime image.
//!
//! A session that outlives an update still reaches the live resident: the
//! hook bridge hands a hook from an older copy to the live copy's path when
//! the two are the same file (`hook_bridge_successor`).
//!
//! The reconciliation pass still repins those artifacts: `hook-launch-scan`
//! reads the digest in the path, not the file. An install that still uses an
//! older digest finds that its copy no longer hashes to the digest and
//! publishes it again (`durable_hook_runtime`), which replaces the link with a
//! fresh file.
//!
//! Everything here is fail-closed. The current copy must be a regular file
//! owned by this user, writable by no one else, in a directory no one else
//! can write, whose bytes hash to the requested digest, and the link must
//! name that same unchanged file. An older copy is relinked only when its
//! directory is a private directory of this user holding nothing but the
//! runtime, the
//! runtime is a regular file owned by this user on the same device, and
//! neither changed within the minimum age, so a copy another process is
//! publishing or verifying right now is left alone. POSIX only: Windows keeps
//! a running image's file locked, so it answers `unsupported`.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

const COMMAND: &str = "durable-runtime-collapse";
const SCHEMA: &str = "durable-runtime-collapse.v1";
const MAX_REQUEST_BYTES: u64 = 16 * 1024;
const STATE_DIR_NAME: &str = "native-runtime";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    guard_home: String,
    /// The digest of the runtime this frozen build pins in hook commands.
    current_digest: String,
}

/// What one pass did.
#[derive(Debug, Serialize)]
struct Report {
    outcome: &'static str,
    collapsed: usize,
    /// Bytes of older copies no other name still held when they were relinked.
    reclaimed_bytes: u64,
    kept: BTreeMap<&'static str, u64>,
    budget_exhausted: bool,
    errors: Vec<&'static str>,
}

impl Report {
    fn new(outcome: &'static str) -> Self {
        Self {
            outcome,
            collapsed: 0,
            reclaimed_bytes: 0,
            kept: BTreeMap::new(),
            budget_exhausted: false,
            errors: Vec::new(),
        }
    }
}

pub(crate) fn is_command(command: &str) -> bool {
    command == COMMAND
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "durable_runtime_collapse_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("durable_runtime_collapse_request_too_large".to_owned());
    }
    let request: Request = serde_json::from_slice(&bytes)
        .map_err(|_| "durable_runtime_collapse_request_invalid".to_owned())?;
    if request.schema != SCHEMA
        || !is_digest(&request.current_digest)
        || !Path::new(&request.guard_home).is_absolute()
    {
        return Err("durable_runtime_collapse_request_invalid".to_owned());
    }
    let state = Path::new(&request.guard_home).join(STATE_DIR_NAME);
    let report = collapse(&state, &request.current_digest, SystemTime::now());
    serde_json::to_vec(&report)
        .map_err(|_| "durable_runtime_collapse_response_unencodable".to_owned())
}

/// The lowercase hex SHA-256 that names a durable copy's directory.
fn is_digest(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(not(unix))]
fn collapse(_state: &Path, _digest: &str, _now: SystemTime) -> Report {
    Report::new("unsupported")
}

#[cfg(unix)]
use posix::collapse;

#[cfg(unix)]
mod posix {
    use std::ffi::OsString;
    use std::fs::{self, File, Metadata};
    use std::io::{ErrorKind, Read};
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    use std::path::Path;
    use std::time::{Duration, Instant, SystemTime};

    use sha2::{Digest, Sha256};

    use super::{is_digest, Report};

    const RUNTIME_NAME: &str = "hol-guard-runtime";
    const LINK_TEMP_NAME: &str = ".hol-guard-runtime.collapse.tmp";
    /// Long past any publish or verification of a copy, which takes seconds.
    pub(super) const MIN_AGE: Duration = Duration::from_secs(24 * 60 * 60);
    /// Relinks per pass; entries that are kept cost an lstat and do not count,
    /// so every pass reaches copies an earlier pass left behind.
    const MAX_COLLAPSES: usize = 2000;
    const TIME_BUDGET: Duration = Duration::from_secs(30);
    const MAX_ERRORS: usize = 10;
    const HASH_CHUNK: usize = 1024 * 1024;

    enum Outcome {
        Collapsed(u64),
        Kept(&'static str),
    }

    impl Report {
        fn keep(&mut self, reason: &'static str) {
            *self.kept.entry(reason).or_default() += 1;
        }

        fn error(&mut self, error: &'static str) {
            if self.errors.len() < MAX_ERRORS {
                self.errors.push(error);
            }
        }

        fn unavailable(mut self, error: &'static str) -> Self {
            self.outcome = "unavailable";
            self.error(error);
            self
        }
    }

    pub(super) fn collapse(state: &Path, digest: &str, now: SystemTime) -> Report {
        let started = Instant::now();
        let mut report = Report::new("ok");
        let uid = nix::unistd::getuid().as_raw();
        match fs::symlink_metadata(state) {
            Ok(metadata) if private_directory(&metadata, uid) => {}
            Ok(_) => return report.unavailable("state_dir_untrusted"),
            Err(error) if error.kind() == ErrorKind::NotFound => return report,
            Err(_) => return report.unavailable("state_dir_unreadable"),
        }
        let current_path = state.join(digest).join(RUNTIME_NAME);
        let Some(current) = verified_current(&current_path, digest, uid) else {
            return report.unavailable("current_runtime_unverified");
        };
        let Ok(entries) = fs::read_dir(state) else {
            return report.unavailable("state_dir_unreadable");
        };
        for entry in entries {
            if report.collapsed >= MAX_COLLAPSES || started.elapsed() >= TIME_BUDGET {
                report.budget_exhausted = true;
                break;
            }
            let Ok(entry) = entry else {
                report.keep("unreadable_entry");
                continue;
            };
            let name = entry.file_name();
            let Some(name) = name.to_str() else {
                continue;
            };
            if !is_digest(name) || name == digest {
                continue;
            }
            match relink(&state.join(name), &current_path, &current, uid, now) {
                Ok(Outcome::Collapsed(bytes)) => {
                    report.collapsed += 1;
                    report.reclaimed_bytes = report.reclaimed_bytes.saturating_add(bytes);
                }
                Ok(Outcome::Kept(reason)) => report.keep(reason),
                Err(error) => report.error(error),
            }
        }
        report
    }

    /// A real directory of this user that no one else can add entries to.
    fn private_directory(metadata: &Metadata, uid: u32) -> bool {
        metadata.is_dir() && metadata.uid() == uid && metadata.permissions().mode() & 0o022 == 0
    }

    /// A regular file of this user that only this user can write and can run.
    fn private_runtime(metadata: &Metadata, uid: u32) -> bool {
        let mode = metadata.permissions().mode();
        metadata.is_file() && metadata.uid() == uid && mode & 0o022 == 0 && mode & 0o100 != 0
    }

    /// The current copy's metadata, when it is a private regular file of this
    /// user, in a private directory, whose bytes hash to `digest` and that did
    /// not change while hashed.
    fn verified_current(path: &Path, digest: &str, uid: u32) -> Option<Metadata> {
        let directory = fs::symlink_metadata(path.parent()?).ok()?;
        let before = fs::symlink_metadata(path).ok()?;
        if !private_directory(&directory, uid) || !private_runtime(&before, uid) {
            return None;
        }
        let mut file = File::open(path).ok()?;
        let opened = file.metadata().ok()?;
        if !same_file(&opened, &before) {
            return None;
        }
        let mut hasher = Sha256::new();
        let mut buffer = vec![0_u8; HASH_CHUNK];
        loop {
            let read = file.read(&mut buffer).ok()?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
        }
        let after = fs::symlink_metadata(path).ok()?;
        // A chmod or chown changes ctime; a write changes mtime.
        let unchanged = same_contents(&after, &before)
            && after.mode() == before.mode()
            && after.ctime() == before.ctime()
            && after.ctime_nsec() == before.ctime_nsec();
        (unchanged && hex::encode(hasher.finalize()) == digest).then_some(before)
    }

    fn same_file(left: &Metadata, right: &Metadata) -> bool {
        left.dev() == right.dev() && left.ino() == right.ino()
    }

    fn same_contents(left: &Metadata, right: &Metadata) -> bool {
        same_file(left, right)
            && left.len() == right.len()
            && left.mtime() == right.mtime()
            && left.mtime_nsec() == right.mtime_nsec()
    }

    fn older_than_min_age(metadata: &Metadata, now: SystemTime) -> bool {
        metadata
            .modified()
            .ok()
            .and_then(|modified| now.duration_since(modified).ok())
            .is_some_and(|age| age >= MIN_AGE)
    }

    /// Replace one older copy's directory entry with a hard link to the
    /// current copy, or say why it was kept.
    fn relink(
        directory: &Path,
        current_path: &Path,
        current: &Metadata,
        uid: u32,
        now: SystemTime,
    ) -> Result<Outcome, &'static str> {
        let directory_metadata = fs::symlink_metadata(directory).map_err(|_| "entry_unreadable")?;
        if !private_directory(&directory_metadata, uid) {
            return Ok(Outcome::Kept("untrusted_directory"));
        }
        let mut names: Vec<OsString> = Vec::new();
        for entry in fs::read_dir(directory).map_err(|_| "entry_unreadable")? {
            names.push(entry.map_err(|_| "entry_unreadable")?.file_name());
            if names.len() > 2 {
                return Ok(Outcome::Kept("unexpected_contents"));
            }
        }
        let has_runtime = names.iter().any(|name| name == RUNTIME_NAME);
        let has_temporary = names.iter().any(|name| name == LINK_TEMP_NAME);
        if !has_runtime || names.len() != 1 + usize::from(has_temporary) {
            return Ok(Outcome::Kept("unexpected_contents"));
        }
        let target = directory.join(RUNTIME_NAME);
        let metadata = fs::symlink_metadata(&target).map_err(|_| "entry_unreadable")?;
        if !metadata.is_file() || metadata.uid() != uid {
            return Ok(Outcome::Kept("untrusted_runtime"));
        }
        if metadata.dev() != current.dev() {
            return Ok(Outcome::Kept("other_device"));
        }
        if metadata.ino() == current.ino() {
            return Ok(Outcome::Kept("already_shared"));
        }
        if !older_than_min_age(&metadata, now) || !older_than_min_age(&directory_metadata, now) {
            return Ok(Outcome::Kept("too_recent"));
        }
        let temporary = directory.join(LINK_TEMP_NAME);
        if has_temporary {
            // Left by a pass that stopped between the link and the rename.
            let stray = fs::symlink_metadata(&temporary).map_err(|_| "entry_unreadable")?;
            if stray.is_dir() || stray.uid() != uid {
                return Ok(Outcome::Kept("unexpected_contents"));
            }
            fs::remove_file(&temporary).map_err(|_| "stray_link_unremovable")?;
        }
        fs::hard_link(current_path, &temporary).map_err(|_| "link_failed")?;
        // The link must name the inode that was hashed, unchanged and still
        // private, and the older copy must still be the file that was checked.
        let linked = fs::symlink_metadata(&temporary)
            .is_ok_and(|link| same_contents(&link, current) && private_runtime(&link, uid));
        if !linked {
            let _ = fs::remove_file(&temporary);
            return Ok(Outcome::Kept("current_changed_during_collapse"));
        }
        let unchanged =
            fs::symlink_metadata(&target).is_ok_and(|again| same_file(&again, &metadata));
        if !unchanged {
            let _ = fs::remove_file(&temporary);
            return Ok(Outcome::Kept("changed_during_collapse"));
        }
        if fs::rename(&temporary, &target).is_err() {
            let _ = fs::remove_file(&temporary);
            return Err("rename_failed");
        }
        Ok(Outcome::Collapsed(if metadata.nlink() == 1 {
            metadata.len()
        } else {
            0
        }))
    }
}

#[cfg(all(test, unix))]
#[path = "durable_runtime_collapse_tests.rs"]
mod tests;
