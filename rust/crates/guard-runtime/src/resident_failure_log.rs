//! Bounded, private record of why a managed resident stopped.
//!
//! A one-shot CLI client spawns a supervisor and exits before the resident
//! it asked for has finished its life, so a resident that dies during
//! startup used to leave nothing behind: its stderr went to the null device
//! and the client that would have reported it was already gone. The
//! supervisor owns the resident until it exits, so it writes that stderr and
//! the exit it waited for into one private, size-bounded file next to the
//! rest of the runtime scope state.
//!
//! The supervisor is the only writer. A stderr pump runs on its own thread
//! because a grandchild can hold the pipe open after the resident is gone,
//! but it only collects bytes in memory: a pump that outlives its run can
//! never truncate the record of the run that replaced it.

use std::fs::File;
#[cfg(not(windows))]
use std::io::Read;
use std::io::{Seek, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

/// One supervisor-owned file per runtime scope, beside `restart-budget.json`
/// in `<guard-home>/native-runtime/resident-v3-<digest>/`.
pub(crate) const RESIDENT_FAILURE_FILE_NAME: &str = "resident-stderr.v1.log";
/// A resident that floods stderr must not fill the home. Past this the run's
/// record keeps its first bytes, which hold the startup failure, and drops
/// the rest.
const MAX_RESIDENT_FAILURE_BYTES: usize = 64 * 1024;
#[cfg(not(windows))]
const DRAIN_CHUNK_BYTES: usize = 4096;
/// Another supervisor holds the record only while it rewrites at most
/// `MAX_RESIDENT_FAILURE_BYTES`. A record still locked after these retries is
/// skipped: the supervisor must go on to release its restart charge and its
/// exit hold, and a Windows stop waits on that hold.
const RECORD_LOCK_RETRY_DELAY: Duration = Duration::from_millis(10);
const RECORD_LOCK_RETRIES: u32 = 20;

/// The record of one supervised resident run. Nothing is created until the
/// run has something to report, so a resident that starts, serves and exits
/// cleanly leaves the previous failure in place instead of erasing it.
pub(crate) struct ResidentFailureLog {
    scope: PathBuf,
    file: Option<File>,
    written: usize,
    refused: bool,
}

impl ResidentFailureLog {
    pub(crate) fn for_scope(scope: &Path) -> Self {
        Self {
            scope: scope.to_owned(),
            file: None,
            written: 0,
            refused: false,
        }
    }

    pub(crate) fn path(scope: &Path) -> PathBuf {
        scope.join(RESIDENT_FAILURE_FILE_NAME)
    }

    /// Open this run's record on its first byte, replacing the previous run's
    /// record. The newest failure is the one that explains the denied call.
    fn open(&mut self) -> Option<&mut File> {
        if self.refused {
            return None;
        }
        if self.file.is_none() {
            let Some(file) = self.create() else {
                self.refused = true;
                return None;
            };
            self.file = Some(file);
            self.written = 0;
        }
        self.file.as_mut()
    }

    fn create(&self) -> Option<File> {
        let mut file = open_record(&self.scope)?;
        file.set_len(0).ok()?;
        file.rewind().ok()?;
        Some(file)
    }

    pub(crate) fn append(&mut self, bytes: &[u8]) {
        let remaining = MAX_RESIDENT_FAILURE_BYTES.saturating_sub(self.written);
        if bytes.is_empty() || remaining == 0 {
            return;
        }
        let accepted = remaining.min(bytes.len());
        let Some(file) = self.open() else {
            return;
        };
        if file.write_all(&bytes[..accepted]).is_err() {
            // A broken record must never change the supervised exit result.
            self.file = None;
            self.refused = true;
            return;
        }
        self.written = self.written.saturating_add(accepted);
    }

    /// Append one `native_`-prefixed line of the supervisor's own evidence.
    pub(crate) fn note(&mut self, line: &str) {
        let mut rendered = String::with_capacity(line.len() + 1);
        rendered.push_str(line);
        rendered.push('\n');
        self.append(rendered.as_bytes());
    }
}

/// Open the scope's record without truncating it.
fn open_record(scope: &Path) -> Option<File> {
    let private_root = crate::resident_state::private_root_for_scope(scope).ok()?;
    let path = ResidentFailureLog::path(scope);
    #[cfg(windows)]
    let file = {
        let (file, directory_binding) =
            crate::resident_state::private_lock_file(&path, &private_root).ok()?;
        // The supervisor must not hold a directory barrier for the
        // resident's lifetime; other clients still bind this ancestry.
        drop(directory_binding);
        file
    };
    #[cfg(not(windows))]
    let file = crate::resident_state::private_lock_file(&path, &private_root).ok()?;
    Some(file)
}

/// Read a resident's stderr to end of file, keeping at most the bytes the
/// record can hold. The pipe is drained past that bound so a resident never
/// blocks on a stderr write that nobody is reading, and the bytes are held
/// in memory so only the supervisor ever touches the record file.
#[cfg(not(windows))]
pub(crate) fn collect_resident_stderr(mut reader: impl Read) -> Vec<u8> {
    let mut collected = Vec::new();
    let mut buffer = [0u8; DRAIN_CHUNK_BYTES];
    loop {
        match reader.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                let room = MAX_RESIDENT_FAILURE_BYTES.saturating_sub(collected.len());
                if room > 0 {
                    collected.extend_from_slice(&buffer[..read.min(room)]);
                }
            }
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => {}
            Err(_) => break,
        }
    }
    collected
}

/// Publish one run with no ordering check.
#[cfg(test)]
pub(crate) fn write_run(scope: &Path, stderr: &[u8], note: Option<&str>) {
    let _ = publish_run(ResidentFailureLog::for_scope(scope), stderr, note);
}

/// Publish one supervised run: the resident's stderr, then the supervisor's
/// own classification of the exit. The note is written from space reserved
/// for it, so a resident that floods stderr cannot push the one line that
/// explains the exit out of the record.
fn publish_run(
    mut record: ResidentFailureLog,
    stderr: &[u8],
    note: Option<&str>,
) -> ResidentFailureLog {
    let reserved = note.map_or(0, |note| note.len() + 1);
    let kept = MAX_RESIDENT_FAILURE_BYTES
        .saturating_sub(reserved)
        .min(stderr.len());
    record.append(&stderr[..kept]);
    if let Some(note) = note {
        record.note(note);
    }
    record
}

/// Publish one supervised run unless a later run has already published its
/// own record. A Unix stop no longer waits for the supervisor, so a run that
/// replaced this one can fail and record why while this supervisor is still
/// waiting out its stderr tail; the older record must not erase that newer
/// evidence.
///
/// Runs are ordered by when they started, not by when they wrote: a record
/// takes its run's start as its modification time. Otherwise an older run
/// that writes late, after a newer run has started, would make that newer
/// run's own failure look superseded.
///
/// The check, the rewrite and the timestamp all happen under one exclusive
/// lock on the record, so two supervisors finishing together cannot both
/// pass the check and let the older one overwrite the newer record. The
/// lock goes with the handle when this returns.
pub(crate) fn write_run_unless_superseded(
    scope: &Path,
    stderr: &[u8],
    note: Option<&str>,
    run_started: SystemTime,
) {
    if stderr.is_empty() && note.is_none() {
        // A clean run leaves the previous failure in place.
        return;
    }
    let Some(mut file) = open_record(scope) else {
        return;
    };
    if !lock_record(&file) {
        return;
    }
    // Opening may have just created the file, and a published record is
    // never empty, so only a non-empty record can be a later run's.
    let superseded = file.metadata().is_ok_and(|metadata| {
        metadata.len() > 0
            && metadata
                .modified()
                .is_ok_and(|recorded_run| recorded_run > run_started)
    });
    if superseded || file.set_len(0).is_err() || file.rewind().is_err() {
        return;
    }
    let mut record = ResidentFailureLog::for_scope(scope);
    record.file = Some(file);
    if let Some(file) = publish_run(record, stderr, note).file {
        let _ = file.set_modified(run_started);
    }
}

fn lock_record(file: &File) -> bool {
    for attempt in 0..=RECORD_LOCK_RETRIES {
        if fs2::FileExt::try_lock_exclusive(file).is_ok() {
            return true;
        }
        if attempt < RECORD_LOCK_RETRIES {
            std::thread::sleep(RECORD_LOCK_RETRY_DELAY);
        }
    }
    false
}

#[cfg(test)]
#[path = "resident_failure_log_tests.rs"]
mod tests;
