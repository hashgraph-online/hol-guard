//! A durable note of which runtimes this one retired from a shared guard home.
//!
//! Two current installs against one guard home -- a desktop bundle and a
//! package install, say -- evict each other's resident on alternating hooks,
//! because the owner lock is home-wide and a policy snapshot is only admitted
//! by the runtime that compiled it. The counters that saw this
//! (`client_state_foreign_retired` and `client_state_foreign_rejected`) are
//! emitted from short-lived client processes, which never hold the owner lock
//! and so never reach the resident's diagnostic log: their lines go to hook
//! stderr and are discarded. The churn could be felt in a real install but not
//! attributed to the pair of runtimes causing it.
//!
//! Each retirement now adds one count here, in the retiring runtime's own
//! state scope, against the digest of the runtime it retired. The record holds
//! digests, counts and timestamps only. Runtime digests are public build
//! identities, and no request, path, policy or workspace content reaches this
//! file. It is bounded to `MAX_ENTRIES` pairs, and it never fails a hook: a
//! record that cannot be written is dropped.

use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(windows)]
use super::private_file::recover_interrupted_replace;
use super::private_file::{read_private_bytes, write_private};

const RECORD_SCHEMA: &str = "hol-guard-resident-handoff-record.v1";
const RECORD_FILE: &str = "handoff-record.json";
const RECORD_LOCK_FILE: &str = "handoff-record.lock";
/// Enough pairs to show a home being shared by a handful of installs, few
/// enough that the whole record stays well inside the bounded read that
/// `read_private_bytes` allows.
const MAX_ENTRIES: usize = 8;

/// Why a foreign resident was stopped. An orphan was left behind by a runtime
/// nothing still uses; a rejecting resident is live and refusing this
/// runtime's requests, which is the half that repeats.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Retirement {
    Orphaned,
    Rejected,
}

impl Retirement {
    fn as_str(self) -> &'static str {
        match self {
            Retirement::Orphaned => "orphaned",
            Retirement::Rejected => "rejected",
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HandoffRecord {
    schema: String,
    runtime: String,
    entries: Vec<HandoffEntry>,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HandoffEntry {
    foreign: String,
    reason: String,
    count: u64,
    first_unix: u64,
    last_unix: u64,
}

struct RecordLock {
    file: File,
    #[cfg(windows)]
    _directory_binding: guard_runtime_windows_process::PrivateDirectoryBinding,
}

impl Drop for RecordLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

fn is_digest(value: &str) -> bool {
    value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

fn now_unix() -> Result<u64, String> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "native_resident_clock_invalid".to_owned())?
        .as_secs())
}

/// Take the record lock without waiting. A retirement that collides with
/// another process writing the same record loses its count rather than
/// holding up the hook that triggered it.
fn acquire_record_lock(scope: &Path, private_root: &Path) -> Result<RecordLock, String> {
    let path = scope.join(RECORD_LOCK_FILE);
    #[cfg(windows)]
    let (file, directory_binding) =
        crate::resident_state::private_lock_file(&path, private_root)
            .map_err(|_| "native_resident_handoff_record_lock_failed".to_owned())?;
    #[cfg(not(windows))]
    let file = crate::resident_state::private_lock_file(&path, private_root)
        .map_err(|_| "native_resident_handoff_record_lock_failed".to_owned())?;
    fs2::FileExt::try_lock_exclusive(&file).map_err(|error| {
        if crate::resident_state::is_lock_contention(&error) {
            "native_resident_handoff_record_busy".to_owned()
        } else {
            "native_resident_handoff_record_lock_failed".to_owned()
        }
    })?;
    Ok(RecordLock {
        file,
        #[cfg(windows)]
        _directory_binding: directory_binding,
    })
}

/// Read this scope's record when one is already there and it belongs to this
/// runtime. A record that cannot be parsed, carries another schema or names
/// another runtime is not an error here: diagnostics start again from empty
/// rather than refusing to count.
fn read_existing(path: &Path, private_root: &Path, runtime: &str) -> Option<HandoffRecord> {
    let bytes = read_private_bytes(path, private_root, "handoff_record").ok()??;
    let value = crate::strict_json_value(&bytes).ok()?;
    let record = serde_json::from_value::<HandoffRecord>(value).ok()?;
    if record.schema != RECORD_SCHEMA
        || record.runtime != runtime
        || record.entries.len() > MAX_ENTRIES
        || !record
            .entries
            .iter()
            .all(|entry| is_digest(&entry.foreign) && entry.reason.len() <= 16)
    {
        return None;
    }
    Some(record)
}

/// Count one retirement, best effort. Diagnostics must never be the reason a
/// hook fails, so every error -- an unwritable scope, a held lock, a clock
/// that cannot be read -- ends here.
pub(super) fn record(state_base: &Path, ours: &str, theirs: &str, retirement: Retirement) {
    let Ok(scope) = crate::resident_state::state_scope(state_base, ours) else {
        return;
    };
    let _ = record_in_scope(&scope, ours, theirs, retirement);
}

fn record_in_scope(
    scope: &Path,
    ours: &str,
    theirs: &str,
    retirement: Retirement,
) -> Result<(), String> {
    if !is_digest(ours) || !is_digest(theirs) {
        return Err("native_resident_runtime_digest_invalid".to_owned());
    }
    let private_root = crate::resident_state::private_root_for_scope(scope)?;
    let _lock = acquire_record_lock(scope, &private_root)?;
    let path = scope.join(RECORD_FILE);
    #[cfg(windows)]
    recover_interrupted_replace(&path, &private_root)?;
    let now = now_unix()?;
    let mut record = read_existing(&path, &private_root, ours).unwrap_or_else(|| HandoffRecord {
        schema: RECORD_SCHEMA.to_owned(),
        runtime: ours.to_owned(),
        entries: Vec::new(),
    });
    let reason = retirement.as_str();
    match record
        .entries
        .iter_mut()
        .find(|entry| entry.foreign == theirs && entry.reason == reason)
    {
        Some(entry) => {
            entry.count = entry.count.saturating_add(1);
            entry.last_unix = now;
        }
        None => {
            if record.entries.len() >= MAX_ENTRIES {
                // Drop the pair nothing has touched for longest, so a home
                // that has seen many runtimes keeps the ones still churning.
                let stalest = record
                    .entries
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, entry)| entry.last_unix)
                    .map(|(index, _)| index);
                if let Some(index) = stalest {
                    record.entries.remove(index);
                }
            }
            record.entries.push(HandoffEntry {
                foreign: theirs.to_owned(),
                reason: reason.to_owned(),
                count: 1,
                first_unix: now,
                last_unix: now,
            });
        }
    }
    let encoded = serde_json::to_vec(&record)
        .map_err(|_| "native_resident_handoff_record_encode_failed".to_owned())?;
    write_private(&path, &encoded, &private_root)
}

#[cfg(test)]
#[path = "managed_resident_handoff_record_tests.rs"]
mod tests;
