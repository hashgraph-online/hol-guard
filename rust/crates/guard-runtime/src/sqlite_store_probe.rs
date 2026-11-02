//! `sqlite-store-probe --stdin`: prove a Guard store unusable before
//! destructive recovery, and move a quarantined store back when it still
//! passes integrity (`sqlite_store_probe_detail` and
//! `restore_readable_sqlite_store` in `guard/sqlite_recovery.py` before they
//! moved here).
//!
//! A store is proven unusable only when two read-only `quick_check` probes
//! report corruption, the Guard home still accepts a fresh SQLite write in
//! between, and the store, WAL and shared-memory files keep one identity
//! across every probe. A transient I/O failure or a replaced file is never
//! proof.
//!
//! The caller classifies the original error and sends the remaining
//! connection budget of its storage operation; each probe waits at most that
//! long for a lock.

use std::ffi::c_int;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rusqlite::types::Value as SqlValue;
use rusqlite::{ffi, Connection, OpenFlags, OptionalExtension};
use serde::Deserialize;
use serde_json::json;

const COMMAND: &str = "sqlite-store-probe";
const SCHEMA: &str = "sqlite-store-probe.v1";
const MAX_REQUEST_BYTES: u64 = 64 * 1024;
const PROBE_WAIT: Duration = Duration::from_secs(1);
const WRITE_PROBE_WAIT: Duration = Duration::from_millis(100);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    schema: String,
    /// `detail` revalidates `path`; `restore` moves `quarantined` to `path`.
    op: String,
    path: String,
    #[serde(default)]
    guard_home: Option<String>,
    #[serde(default)]
    quarantined: Option<String>,
    /// The remaining connection budget of the caller's storage operation.
    wait_seconds: f64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Fatal,
    Healthy,
    Io,
    Unknown,
}

impl State {
    fn as_str(self) -> &'static str {
        match self {
            Self::Fatal => "fatal",
            Self::Healthy => "healthy",
            Self::Io => "io",
            Self::Unknown => "unknown",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Detail {
    proven_unusable: bool,
    first_state: State,
    second_state: Option<State>,
    guard_home_accepts_write: Option<bool>,
    identity_stable: bool,
}

/// `(st_dev, st_ino, st_size, st_mtime_ns, st_ctime_ns)` of one file.
type Stamp = [i128; 5];

pub(crate) fn is_command(command: &str) -> bool {
    command == COMMAND
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "sqlite_store_probe_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("sqlite_store_probe_request_too_large".to_owned());
    }
    let invalid = || "sqlite_store_probe_request_invalid".to_owned();
    let request: Request = serde_json::from_slice(&bytes).map_err(|_| invalid())?;
    let wait = Duration::try_from_secs_f64(request.wait_seconds)
        .ok()
        .filter(|wait| !wait.is_zero())
        .ok_or_else(invalid)?;
    let path = absolute(&request.path).ok_or_else(invalid)?;
    if request.schema != SCHEMA {
        return Err(invalid());
    }
    let answer = match (request.op.as_str(), request.guard_home, request.quarantined) {
        ("detail", Some(guard_home), None) => {
            let guard_home = absolute(&guard_home).ok_or_else(invalid)?;
            let detail = detail(
                &path,
                |path| probe(path, PROBE_WAIT.min(wait)),
                || guard_home_accepts_write(&guard_home, WRITE_PROBE_WAIT.min(wait)),
            );
            json!({
                "proven_unusable": detail.proven_unusable,
                "first_state": detail.first_state.as_str(),
                "second_state": detail.second_state.map(State::as_str),
                "guard_home_accepts_write": detail.guard_home_accepts_write,
                "identity_stable": detail.identity_stable,
            })
        }
        ("restore", None, Some(quarantined)) => {
            let quarantined = absolute(&quarantined).ok_or_else(invalid)?;
            json!({"restored": restore(&path, &quarantined, PROBE_WAIT.min(wait))})
        }
        _ => return Err(invalid()),
    };
    serde_json::to_vec(&answer).map_err(|_| "sqlite_store_probe_response_unencodable".to_owned())
}

fn absolute(path: &str) -> Option<PathBuf> {
    let path = PathBuf::from(path);
    path.is_absolute().then_some(path)
}

/// Probes twice around a write check, refusing proof once any file changes.
fn detail(
    path: &Path,
    mut probe: impl FnMut(&Path) -> State,
    accepts_write: impl FnOnce() -> bool,
) -> Detail {
    let initial = identity(path);
    let first_state = probe(path);
    let confirmed = identity(path);
    let unproven = |identity_stable, accepts_write| Detail {
        proven_unusable: false,
        first_state,
        second_state: None,
        guard_home_accepts_write: accepts_write,
        identity_stable,
    };
    if initial != confirmed || first_state != State::Fatal {
        return unproven(initial == confirmed, None);
    }
    if !accepts_write() {
        return unproven(true, Some(false));
    }
    let second_state = probe(path);
    let identity_stable = confirmed == identity(path);
    Detail {
        proven_unusable: second_state == State::Fatal && identity_stable,
        first_state,
        second_state: Some(second_state),
        guard_home_accepts_write: Some(true),
        identity_stable,
    }
}

fn probe(path: &Path, wait: Duration) -> State {
    let result = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .and_then(|connection| {
        connection.busy_timeout(wait)?;
        connection
            .query_row("pragma quick_check", [], |row| row.get::<_, SqlValue>(0))
            .optional()
    });
    match result {
        Ok(Some(SqlValue::Text(text))) if text == "ok" => State::Healthy,
        Ok(_) => State::Fatal,
        Err(rusqlite::Error::SqliteFailure(failure, _)) => classify(failure.extended_code),
        Err(_) => State::Unknown,
    }
}

/// Routes on the primary code an extended code keeps in its low byte.
fn classify(extended_code: c_int) -> State {
    match extended_code & 0xFF {
        ffi::SQLITE_CORRUPT | ffi::SQLITE_NOTADB => State::Fatal,
        ffi::SQLITE_IOERR => State::Io,
        _ => State::Unknown,
    }
}

/// Whether a fresh database in the Guard home takes a write, so a failing
/// disk or full volume is never mistaken for a corrupt store.
fn guard_home_accepts_write(guard_home: &Path, wait: Duration) -> bool {
    let mut nonce = [0_u8; 16];
    if getrandom::fill(&mut nonce).is_err() {
        return false;
    }
    let probe = guard_home.join(format!("storage-probe-{}.db", hex::encode(nonce)));
    let written = write_probe(&probe, wait).is_ok() && probe.is_file();
    let _ = fs::remove_file(&probe);
    written
}

fn write_probe(path: &Path, wait: Duration) -> rusqlite::Result<()> {
    let connection = Connection::open(path)?;
    connection.busy_timeout(wait)?;
    connection.execute_batch(
        "begin; create table probe (value integer); insert into probe values (1); commit;",
    )
}

/// Moves a quarantined store and its sidecars back when the store still
/// passes `quick_check`, undoing every move when one fails. The store moves
/// last, so a helper stopped part way never leaves it beside a missing WAL;
/// the caller finds the split sidecars still quarantined beside it.
fn restore(destination: &Path, quarantined: &Path, wait: Duration) -> bool {
    if fs::symlink_metadata(destination).is_ok() || probe(quarantined, wait) != State::Healthy {
        return false;
    }
    let sidecars: Vec<(PathBuf, PathBuf)> = ["-wal", "-shm"]
        .into_iter()
        .map(|suffix| (suffixed(quarantined, suffix), suffixed(destination, suffix)))
        .filter(|(source, _)| source.exists() && !source.is_symlink())
        .collect();
    let mut moved = 0;
    let complete = sidecars.iter().all(|(source, target)| {
        let renamed = fs::rename(source, target).is_ok();
        moved += usize::from(renamed);
        renamed
    }) && fs::rename(quarantined, destination).is_ok();
    if !complete {
        for (source, target) in sidecars[..moved].iter().rev() {
            let _ = fs::rename(target, source);
        }
    }
    complete
}

fn identity(path: &Path) -> [Option<Stamp>; 3] {
    [
        stamp(path),
        stamp(&suffixed(path, "-wal")),
        stamp(&suffixed(path, "-shm")),
    ]
}

fn stamp(path: &Path) -> Option<Stamp> {
    let metadata = fs::metadata(path).ok()?;
    let nanos = |time: std::io::Result<SystemTime>| {
        time.ok()
            .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
            .map_or(0, |since| {
                i128::try_from(since.as_nanos()).unwrap_or(i128::MAX)
            })
    };
    // Windows reports its creation time as `st_ctime`.
    let stamp = [
        0,
        0,
        i128::from(metadata.len()),
        nanos(metadata.modified()),
        nanos(metadata.created()),
    ];
    #[cfg(unix)]
    let stamp = {
        use std::os::unix::fs::MetadataExt;
        [
            i128::from(metadata.dev()),
            i128::from(metadata.ino()),
            stamp[2],
            stamp[3],
            i128::from(metadata.ctime()) * 1_000_000_000 + i128::from(metadata.ctime_nsec()),
        ]
    };
    Some(stamp)
}

fn suffixed(path: &Path, suffix: &str) -> PathBuf {
    let mut text = path.as_os_str().to_owned();
    text.push(suffix);
    PathBuf::from(text)
}

#[cfg(test)]
#[path = "sqlite_store_probe_tests.rs"]
mod tests;
