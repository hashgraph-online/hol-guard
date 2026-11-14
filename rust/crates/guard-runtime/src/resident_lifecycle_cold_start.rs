//! The cold-start bands the lifecycle journal counts beside its events: how
//! long each new resident took to answer its first request.

use std::path::Path;
use std::time::Duration;

use super::{update_at, HourCounts, Journal, Totals};

/// How long a cold start took, from the spawn to the first answer the new
/// resident gave. The bands are the readiness budget's: a start inside a
/// second is the normal case, five seconds is the most a hook may wait, and
/// anything slower missed it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ColdStart {
    WithinOneSecond,
    WithinFiveSeconds,
    Slower,
}

impl ColdStart {
    fn of(elapsed: Duration) -> Self {
        if elapsed <= Duration::from_secs(1) {
            Self::WithinOneSecond
        } else if elapsed <= Duration::from_secs(5) {
            Self::WithinFiveSeconds
        } else {
            Self::Slower
        }
    }
}

impl HourCounts {
    fn band(&mut self, band: ColdStart) -> &mut u32 {
        match band {
            ColdStart::WithinOneSecond => &mut self.cold_starts_within_1s,
            ColdStart::WithinFiveSeconds => &mut self.cold_starts_within_5s,
            ColdStart::Slower => &mut self.cold_starts_slower,
        }
    }

    pub(super) fn absorb_cold_starts(&mut self, other: &Self) {
        self.cold_starts_within_1s = self
            .cold_starts_within_1s
            .saturating_add(other.cold_starts_within_1s);
        self.cold_starts_within_5s = self
            .cold_starts_within_5s
            .saturating_add(other.cold_starts_within_5s);
        self.cold_starts_slower = self
            .cold_starts_slower
            .saturating_add(other.cold_starts_slower);
    }
}

impl Totals {
    pub(super) fn add_cold_starts(&mut self, bucket: &HourCounts) {
        self.cold_starts_within_1s = self
            .cold_starts_within_1s
            .saturating_add(bucket.cold_starts_within_1s);
        self.cold_starts_within_5s = self
            .cold_starts_within_5s
            .saturating_add(bucket.cold_starts_within_5s);
        self.cold_starts_slower = self
            .cold_starts_slower
            .saturating_add(bucket.cold_starts_slower);
    }
}

impl Journal {
    /// Count a cold start's band. It is a measurement of the start already
    /// counted, not an event of its own, so the last event stays the start.
    pub(super) fn apply_cold_start(&mut self, band: ColdStart, now: u64) {
        let counter = self.hour(now).band(band);
        *counter = counter.saturating_add(1);
    }
}

/// Count how long a cold start took to answer, without waiting for the lock.
/// The client is still holding the answer it is about to return, so a busy
/// journal loses the band rather than delay it.
pub(in crate::managed_resident) fn record_cold_start_without_waiting(
    scope: &Path,
    elapsed: Duration,
) {
    let _ = update_at(scope, None, false, |journal, now| {
        journal.apply_cold_start(ColdStart::of(elapsed), now);
    });
}
