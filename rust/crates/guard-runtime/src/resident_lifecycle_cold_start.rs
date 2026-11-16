//! The cold-start bands the lifecycle journal counts beside its events: how
//! long each new resident took to become ready to serve.

use std::path::Path;
use std::time::Duration;

use super::{update_at, HourCounts, Journal, Totals};

/// How long a cold start took, from the resident entering its serve path to
/// its transport publishing readiness. The bands are the readiness budget's: a start inside a
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

/// Count how long this resident took from entering its serve path to its
/// transport publishing readiness. Process exec and supervisor time before
/// that are not included.
///
/// The transport calls this only after its listener is bound and its state is
/// published, so a start that fails before then, including a failed bind, is
/// counted as a failed or premature exit and gets no band. The write runs on
/// its own thread, so the journal lock and its file sync never delay the
/// first request.
pub(in crate::managed_resident) fn record_ready_in_background(scope: &Path, elapsed: Duration) {
    let scope = scope.to_path_buf();
    let _ = std::thread::Builder::new()
        .name("hol-guard-lifecycle-cold-start".to_owned())
        .spawn(move || record_ready(&scope, elapsed));
}

pub(super) fn record_ready(scope: &Path, elapsed: Duration) {
    let _ = update_at(scope, None, true, |journal, now| {
        journal.apply_cold_start(ColdStart::of(elapsed), now);
    });
}
