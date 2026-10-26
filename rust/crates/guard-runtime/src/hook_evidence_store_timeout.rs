//! The writer's sqlite-timeout seam.
//!
//! `sqlite_tuning._sqlite_wait_limit_seconds` reads a `ContextVar` the writer
//! installs for the duration of one batch. A thread-local is the same thing
//! for the writer's single worker thread, so the override seam no longer needs
//! Python.

use std::cell::Cell;
use std::num::NonZeroU32;
use std::thread::ThreadId;

use guard_command::hook_evidence_writer::SqliteTimeoutApi;

/// `sqlite_tuning._DEFAULT_SQLITE_CONNECT_TIMEOUT_SECONDS` in milliseconds.
const DEFAULT_SQLITE_TIMEOUT_MS: u32 = 30_000;
/// `sqlite_tuning._MAX_INTERNAL_HOOK_SQLITE_TIMEOUT_MS`.
const MAX_INTERNAL_HOOK_SQLITE_TIMEOUT_MS: u32 = 250;
/// `sqlite_tuning._INTERNAL_HOOK_SQLITE_TIMEOUT_ENV`.
const INTERNAL_HOOK_SQLITE_TIMEOUT_ENV: &str = "HOL_GUARD_INTERNAL_HOOK_SQLITE_TIMEOUT_MS";

thread_local! {
    /// `sqlite_tuning._sqlite_connect_timeout_override` — the per-batch
    /// override the writer installs around its store calls.
    static SQLITE_TIMEOUT_MS: Cell<Option<NonZeroU32>> = const { Cell::new(None) };
}

/// The writer's sqlite-timeout seam, installed around one batch of calls.
pub(crate) struct NativeSqliteTimeout;

impl SqliteTimeoutApi for NativeSqliteTimeout {
    fn sqlite_timeout_override(&self, timeout_ms: NonZeroU32) -> Box<dyn std::any::Any + Send> {
        let previous = SQLITE_TIMEOUT_MS.with(|cell| cell.replace(Some(timeout_ms)));
        Box::new(SqliteTimeoutReset {
            previous,
            owner: std::thread::current().id(),
        })
    }
}

/// `ContextVar.reset(token)` — restores whatever the override replaced.
struct SqliteTimeoutReset {
    previous: Option<NonZeroU32>,
    owner: ThreadId,
}

impl Drop for SqliteTimeoutReset {
    fn drop(&mut self) {
        // A `ContextVar` token belongs to the context that set it. The seam
        // hands back a `Send` box, so a drop on another thread would reset a
        // override that thread never installed; leave it alone.
        if std::thread::current().id() == self.owner {
            SQLITE_TIMEOUT_MS.with(|cell| cell.set(self.previous));
        }
    }
}

/// `sqlite_tuning._sqlite_wait_limit_seconds`, in milliseconds: the installed
/// override first, then the internal-hook environment bound, then the default
/// connect timeout.
pub(crate) fn sqlite_timeout_ms() -> u32 {
    if let Some(timeout) = SQLITE_TIMEOUT_MS.with(Cell::get) {
        return timeout.get();
    }
    std::env::var(INTERNAL_HOOK_SQLITE_TIMEOUT_ENV)
        .ok()
        .and_then(|raw| internal_hook_timeout_ms(&raw))
        .unwrap_or(DEFAULT_SQLITE_TIMEOUT_MS)
}

/// The internal-hook bound as Python reads it: integers only, a non-positive
/// value ignored, the rest capped. A float or trailing text leaves the
/// default in place.
pub(crate) fn internal_hook_timeout_ms(raw: &str) -> Option<u32> {
    match raw.trim().parse::<i64>().ok()? {
        milliseconds if milliseconds > 0 => Some(
            u64::try_from(milliseconds)
                .unwrap_or(u64::MAX)
                .min(u64::from(MAX_INTERNAL_HOOK_SQLITE_TIMEOUT_MS)) as u32,
        ),
        _ => None,
    }
}
