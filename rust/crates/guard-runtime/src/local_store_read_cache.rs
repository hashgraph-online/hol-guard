//! Read-only `guard.db` connections kept from one call to the next.
//!
//! Opening the store costs a file open and SQLite's schema read on every
//! call. A connection a call hands back is kept for the next call that reads
//! the same file: the same canonical path, still naming the same file (its
//! device and inode), so a store replaced at that path opens fresh. The file
//! must name the same file just before and just after a connection opens, or
//! the connection is never kept; a kept connection holds its file open, so
//! no other file can take that identity meanwhile. A call still opens its own
//! read transaction, which sees every commit made before it. Only a
//! connection whose call left no transaction open is kept, and a caller
//! leaves no other state on it but cached statements: the hook probes, which
//! shorten the busy timeout, open their own. Where std names no file identity
//! (anywhere but Unix), every call opens fresh, as does any call that finds
//! the cache poisoned.

use std::ops::Deref;
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use rusqlite::Connection;

use super::{open_read_only, StoreReadError};

/// Idle connections kept across every store; the oldest is closed for more.
const MAX_IDLE: usize = 4;

/// The file a connection was opened on. Never made where std names no
/// file identity.
#[cfg_attr(not(unix), allow(dead_code))]
#[derive(Debug, Clone, PartialEq, Eq)]
struct FileKey {
    path: PathBuf,
    device: u64,
    inode: u64,
}

struct Idle {
    key: FileKey,
    connection: Connection,
}

static IDLE: Mutex<Vec<Idle>> = Mutex::new(Vec::new());

/// A read-only store connection, kept for a later call when dropped.
pub(crate) struct CachedConnection {
    /// Taken only when the connection is dropped.
    connection: Option<Connection>,
    /// `None` for a connection that is never kept.
    key: Option<FileKey>,
}

impl Deref for CachedConnection {
    type Target = Connection;

    fn deref(&self) -> &Connection {
        self.connection
            .as_ref()
            .unwrap_or_else(|| unreachable!("the connection is taken only on drop"))
    }
}

impl Drop for CachedConnection {
    fn drop(&mut self) {
        let (Some(connection), Some(key)) = (self.connection.take(), self.key.take()) else {
            return;
        };
        if let Ok(mut idle) = IDLE.lock() {
            keep(&mut idle, key, connection);
        }
    }
}

/// `open_read_only(store_path)`, reusing a connection a previous call kept
/// for the same file.
pub(crate) fn open_read_only_cached(
    store_path: &Path,
) -> Result<Option<CachedConnection>, StoreReadError> {
    let Some(key) = file_key(store_path) else {
        return Ok(
            open_read_only(store_path)?.map(|connection| CachedConnection {
                connection: Some(connection),
                key: None,
            }),
        );
    };
    let reused = IDLE.lock().ok().and_then(|mut idle| take(&mut idle, &key));
    if let Some(connection) = reused {
        return Ok(Some(CachedConnection {
            connection: Some(connection),
            key: Some(key),
        }));
    }
    let Some(connection) = open_read_only(store_path)? else {
        return Ok(None);
    };
    // A file replaced while the connection opened leaves it unkept.
    let kept = file_key(store_path).filter(|after| *after == key);
    Ok(Some(CachedConnection {
        connection: Some(connection),
        key: kept,
    }))
}

/// A kept connection to `key`'s file, the most recently returned first.
fn take(idle: &mut Vec<Idle>, key: &FileKey) -> Option<Connection> {
    forget_replaced(idle, key);
    let at = idle.iter().rposition(|held| held.key == *key)?;
    Some(idle.remove(at).connection)
}

/// Keep `connection` for a later call on `key`'s file. A transaction its
/// call left open is never handed to another call.
fn keep(idle: &mut Vec<Idle>, key: FileKey, connection: Connection) {
    if !connection.is_autocommit() {
        return;
    }
    forget_replaced(idle, &key);
    if idle.len() >= MAX_IDLE {
        idle.remove(0);
    }
    idle.push(Idle { key, connection });
}

/// Close the kept connections to a file no longer at `key`'s path.
fn forget_replaced(idle: &mut Vec<Idle>, key: &FileKey) {
    idle.retain(|held| held.key.path != key.path || held.key == *key);
}

#[cfg(unix)]
fn file_key(store_path: &Path) -> Option<FileKey> {
    use std::os::unix::fs::MetadataExt;
    let path = std::fs::canonicalize(store_path).ok()?;
    let metadata = std::fs::metadata(&path).ok()?;
    metadata.is_file().then(|| FileKey {
        device: metadata.dev(),
        inode: metadata.ino(),
        path,
    })
}

#[cfg(not(unix))]
fn file_key(_store_path: &Path) -> Option<FileKey> {
    None
}

#[cfg(all(test, unix))]
#[path = "local_store_read_cache_tests.rs"]
mod tests;
