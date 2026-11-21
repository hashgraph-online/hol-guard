//! Counts of declarative command work, for scale measurement.
//!
//! Catalog-scale acceptance asks whether disabled entries change per-hook
//! work. These counters record the active extension set a decision used and
//! how many candidate rules the declarative pass considered and ran. They
//! hold numbers only, never rule IDs or command text.
//!
//! Everything but the process-wide maximum is kept per thread and cleared at
//! the start of each resident request, because a request is evaluated and
//! noted on the same worker thread while other workers run their own
//! requests. A request that compiles no controls and runs no pass must report
//! its own absence of work rather than an earlier request's counts.

use std::cell::Cell;
use std::sync::atomic::{AtomicUsize, Ordering};

static MAX_CANDIDATES: AtomicUsize = AtomicUsize::new(0);

thread_local! {
    static LAST_PASS: Cell<(usize, usize)> = const { Cell::new((0, 0)) };
    static ACTIVE_EXTENSIONS: Cell<Option<usize>> = const { Cell::new(None) };
}

/// The declarative work one resident request did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CommandWorkStats {
    /// Extensions active in the controls this request decided with, or
    /// `None` when it reached no controls at all.
    pub active_extensions: Option<usize>,
    /// Candidate rules this request's declarative pass considered.
    pub last_candidates: usize,
    /// Candidates in that pass whose extension was active and whose matcher ran.
    pub last_evaluated: usize,
    /// The largest candidate count any pass in this process considered.
    pub max_candidates: usize,
}

/// Clears the per-request counts. Called once before a resident request is
/// evaluated, so the counts a snapshot reports are that request's own.
pub fn begin_request() {
    LAST_PASS.with(|last| last.set((0, 0)));
    ACTIVE_EXTENSIONS.with(|active| active.set(None));
}

pub fn snapshot() -> CommandWorkStats {
    let (last_candidates, last_evaluated) = LAST_PASS.with(Cell::get);
    CommandWorkStats {
        active_extensions: ACTIVE_EXTENSIONS.with(Cell::get),
        last_candidates,
        last_evaluated,
        max_candidates: MAX_CANDIDATES.load(Ordering::Relaxed),
    }
}

pub(crate) fn record_active(count: usize) {
    ACTIVE_EXTENSIONS.with(|active| active.set(Some(count)));
}

pub(crate) fn record_pass(candidates: usize, evaluated: usize) {
    LAST_PASS.with(|last| last.set((candidates, evaluated)));
    MAX_CANDIDATES.fetch_max(candidates, Ordering::Relaxed);
}
