//! Whether a hook's app is one Guard protects, read once per burst.
//!
//! Every hook reads the store's managed-install rows before admission. Read
//! one by one, a burst of hooks each opened the store and parsed its schema,
//! and the opens queued on SQLite's locks for longer than the hooks'
//! deadlines. Here one read answers every hook of the same app that arrived
//! before it began, so each hook still sees the store as it stood at or
//! after its arrival.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, OnceLock, PoisonError};
use std::time::Instant;

/// Apps whose last read is kept. Names come from authenticated routes, but a
/// full table is cleared rather than grown.
const MAX_APPS: usize = 64;

#[derive(Default)]
struct Read {
    started: Option<Instant>,
    unmanaged: bool,
}

pub(super) struct ManagedReads {
    apps: Mutex<HashMap<String, Arc<Mutex<Read>>>>,
}

impl ManagedReads {
    pub(super) fn new() -> Self {
        Self {
            apps: Mutex::new(HashMap::new()),
        }
    }

    /// Answers whether `app` is unmanaged for a hook that arrived at
    /// `arrived`: a read that began at or after then answers it, otherwise
    /// it runs `read` itself while later arrivals wait for its answer.
    pub(super) fn unmanaged(
        &self,
        app: &str,
        arrived: Instant,
        read: impl FnOnce() -> bool,
    ) -> bool {
        let slot = {
            let mut apps = self.apps.lock().unwrap_or_else(PoisonError::into_inner);
            if apps.len() >= MAX_APPS && !apps.contains_key(app) {
                apps.clear();
            }
            Arc::clone(apps.entry(app.to_owned()).or_default())
        };
        let mut last = slot.lock().unwrap_or_else(PoisonError::into_inner);
        if last.started.is_some_and(|started| started >= arrived) {
            return last.unmanaged;
        }
        let started = Instant::now();
        let unmanaged = read();
        *last = Read {
            started: Some(started),
            unmanaged,
        };
        unmanaged
    }
}

/// The daemon's shared reads.
pub(super) fn shared() -> &'static ManagedReads {
    static READS: OnceLock<ManagedReads> = OnceLock::new();
    READS.get_or_init(ManagedReads::new)
}

#[cfg(test)]
#[path = "daemon_edge_hook_managed_tests.rs"]
mod tests;
