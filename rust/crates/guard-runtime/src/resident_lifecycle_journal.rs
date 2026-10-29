//! What this install's managed resident has been doing lately, in counts.
//!
//! The failure log next door keeps the last unhealthy run's stderr so a person
//! can read why one run ended. That record is deliberately narrow: it is
//! overwritten by the next failure, it holds no record of the runs that
//! succeeded, and a one-shot client that spawns a resident and exits leaves no
//! trace of the attempt at all. Nothing in the runtime could therefore answer
//! the question a support request actually asks -- is this install's enforcement
//! healthy, or has it been failing all day?
//!
//! This journal answers that and nothing more. It holds the last day's counts
//! of starts, the three ways a run ends, and starts the restart budget refused,
//! plus a fixed code naming the last event and when it happened. The day really
//! does roll: the counts live in hourly buckets and a bucket leaves the journal
//! only once it is itself a day old, so a failure recorded minutes ago is never
//! dropped because an older event happened to open the window.
//!
//! There is no path, no command, no process id, no stderr and no free text in
//! it. The shareable artifact is [`health`]'s snapshot, whose times are ages in
//! seconds rather than wall-clock instants; it can be read out to a user or
//! carried in a support bundle without anybody having to redact it first. The
//! file behind it is an ordinary private runtime file: it holds the same counts
//! against coarse hourly keys, which is a weaker trail than a log but still a
//! trail, so it stays inside the private state directory. The shape is fixed
//! either way, so the file stays a few hundred bytes however long an install
//! runs.
//!
//! Every write is best effort. A journal is an observation of the runtime, not
//! a part of it: a busy lock, a full disk or a damaged file must never change
//! whether a resident spawns or how its exit is classified.

use serde::{Deserialize, Serialize};
use std::fs::File;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

#[cfg(windows)]
use super::private_file::recover_interrupted_replace;
use super::private_file::{read_private_bytes, write_private};

/// How finely the day is cut. An hour is coarse enough that the file is a
/// weaker record of when a person was working than any log beside it, and fine
/// enough that a day expires an hour at a time rather than all at once.
const JOURNAL_BUCKET_MS: u64 = 60 * 60 * 1_000;
/// How many of those hours one journal covers. A day is long enough that a user
/// who noticed something this morning can still see it this evening, and short
/// enough that an install which has since been repaired stops reporting the
/// failures it has recovered from.
const JOURNAL_BUCKETS: u64 = 24;
const JOURNAL_WINDOW_MS: u64 = JOURNAL_BUCKETS * JOURNAL_BUCKET_MS;
const JOURNAL_SCHEMA: &str = "hol-guard-resident-lifecycle-journal.v1";
const JOURNAL_FILE: &str = "lifecycle-journal.json";
const JOURNAL_LOCK_FILE: &str = "lifecycle-journal.lock";
/// A journal write is one small read and write under the lock, and on the exit
/// path a supervisor has nobody waiting on it. Waiting briefly for an ordinary
/// overlap there costs less than losing the event.
const JOURNAL_LOCK_RETRY_DELAY: Duration = Duration::from_millis(10);
const JOURNAL_LOCK_RETRIES: u32 = 20;

/// Something worth counting that happened to this install's resident.
///
/// This is the whole vocabulary of the journal, on the way in and on the way
/// back out: the stored code is read as this enum, so a file somebody edited
/// cannot put a word of its own into a snapshot that is meant to be shareable
/// unread. A caller cannot describe an event in its own words either, which is
/// what keeps a path or a command out of the file by construction rather than
/// by review.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Event {
    /// A resident was started and is running.
    Started,
    /// A run ended the way a healthy one does.
    ExitedOrderly,
    /// A run ended reporting failure.
    ExitedFailed,
    /// A run reported success before it could have served anything.
    ExitedPremature,
    /// The restart budget refused a start because its circuit was open.
    StartRefused,
}

impl Event {
    /// The fixed code written to the file. These are the only strings this
    /// module ever stores beside its own schema.
    const fn code(self) -> &'static str {
        match self {
            Self::Started => "started",
            Self::ExitedOrderly => "exited_orderly",
            Self::ExitedFailed => "exited_failed",
            Self::ExitedPremature => "exited_premature",
            Self::StartRefused => "start_refused",
        }
    }
}

/// One hour's counts, keyed by the hour since the epoch it belongs to.
#[derive(Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct HourCounts {
    hour: u64,
    starts: u32,
    orderly_exits: u32,
    failed_exits: u32,
    premature_exits: u32,
    refused_starts: u32,
}

impl HourCounts {
    fn counter(&mut self, event: Event) -> &mut u32 {
        match event {
            Event::Started => &mut self.starts,
            Event::ExitedOrderly => &mut self.orderly_exits,
            Event::ExitedFailed => &mut self.failed_exits,
            Event::ExitedPremature => &mut self.premature_exits,
            Event::StartRefused => &mut self.refused_starts,
        }
    }

    /// Fold a second record of the same hour into this one. Two can only exist
    /// in a file somebody wrote by hand, but a reader that kept both would let
    /// that file grow without bound.
    fn absorb(&mut self, other: &Self) {
        self.starts = self.starts.saturating_add(other.starts);
        self.orderly_exits = self.orderly_exits.saturating_add(other.orderly_exits);
        self.failed_exits = self.failed_exits.saturating_add(other.failed_exits);
        self.premature_exits = self.premature_exits.saturating_add(other.premature_exits);
        self.refused_starts = self.refused_starts.saturating_add(other.refused_starts);
    }
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema: String,
    hours: Vec<HourCounts>,
    last_event: Option<Event>,
    last_event_ms: u64,
}

/// The day's counts, summed over the hours still inside the window.
#[derive(Debug, Default, PartialEq, Eq)]
struct Totals {
    starts: u32,
    orderly_exits: u32,
    failed_exits: u32,
    premature_exits: u32,
    refused_starts: u32,
}

const fn hour_of(ms: u64) -> u64 {
    ms / JOURNAL_BUCKET_MS
}

impl Journal {
    fn new() -> Self {
        Self {
            schema: JOURNAL_SCHEMA.to_owned(),
            hours: Vec::new(),
            last_event: None,
            last_event_ms: 0,
        }
    }

    /// Drop everything that is no longer part of the day this moment is in.
    ///
    /// An hour is dropped when it is a day old, and also when it is in the
    /// future: a clock that has been set back would otherwise leave counts it
    /// can never expire, reported as a day that never ages. The same bound
    /// applies to the last event, so a stale code cannot outlive its hour.
    fn retain_window(&mut self, now: u64) {
        let current = hour_of(now);
        self.hours
            .retain(|bucket| bucket.hour <= current && current - bucket.hour < JOURNAL_BUCKETS);
        self.hours.sort_by_key(|bucket| bucket.hour);
        self.hours.dedup_by(|later, kept| {
            if later.hour == kept.hour {
                kept.absorb(later);
                true
            } else {
                false
            }
        });
        if self.last_event_ms > now || now - self.last_event_ms >= JOURNAL_WINDOW_MS {
            self.last_event = None;
            self.last_event_ms = 0;
        }
    }

    fn apply(&mut self, event: Event, now: u64) {
        let current = hour_of(now);
        let bucket = match self.hours.iter_mut().find(|bucket| bucket.hour == current) {
            Some(bucket) => bucket,
            None => {
                self.hours.push(HourCounts {
                    hour: current,
                    ..HourCounts::default()
                });
                self.hours.last_mut().expect("bucket just pushed")
            }
        };
        // An install that somehow reaches four billion of anything inside an
        // hour is already past the point where one more matters; it must not be
        // the thing that panics a supervisor on its way out.
        let counter = bucket.counter(event);
        *counter = counter.saturating_add(1);
        self.last_event = Some(event);
        self.last_event_ms = now;
    }

    fn totals(&self) -> Totals {
        let mut totals = Totals::default();
        for bucket in &self.hours {
            totals.starts = totals.starts.saturating_add(bucket.starts);
            totals.orderly_exits = totals.orderly_exits.saturating_add(bucket.orderly_exits);
            totals.failed_exits = totals.failed_exits.saturating_add(bucket.failed_exits);
            totals.premature_exits = totals
                .premature_exits
                .saturating_add(bucket.premature_exits);
            totals.refused_starts = totals.refused_starts.saturating_add(bucket.refused_starts);
        }
        totals
    }
}

/// What a reader is told about this install's recent lifecycle.
#[derive(Debug, Serialize)]
pub(crate) struct LifecycleHealth {
    /// `healthy`, `degraded` or `critical`, derived from the counts below.
    pub state: &'static str,
    pub starts: u32,
    pub orderly_exits: u32,
    pub failed_exits: u32,
    pub premature_exits: u32,
    pub refused_starts: u32,
    /// The fixed code of the most recent event, empty on a journal whose last
    /// event has itself aged out (and then `last_event_age_seconds` is 0). Typed as a fixed string so no text a file
    /// carried can reach a reader through this field.
    pub last_event: &'static str,
    /// How long ago the most recent event was, in seconds. Relative, so a
    /// published snapshot does not carry a wall-clock trail of the user's day.
    pub last_event_age_seconds: u64,
    /// How long ago the oldest hour still counted here began.
    pub window_age_seconds: u64,
}

/// How this install's day reads.
///
/// `critical` is the one state that says enforcement may be absent right now:
/// the last thing that happened was the restart budget refusing a start, so
/// the circuit is open and nothing started in its place.
///
/// `degraded` says the day contains runs that did not end healthily. That is
/// deliberately a property of the window rather than of the last event: an
/// install that crashes every few minutes and recovers in between is not
/// healthy, however good its most recent run looked.
fn health_state(journal: &Journal, totals: &Totals) -> &'static str {
    if journal.last_event == Some(Event::StartRefused) {
        return "critical";
    }
    if totals.failed_exits > 0 || totals.premature_exits > 0 || totals.refused_starts > 0 {
        return "degraded";
    }
    "healthy"
}

struct JournalLock {
    file: File,
    #[cfg(windows)]
    _directory_binding: guard_runtime_windows_process::PrivateDirectoryBinding,
}

impl Drop for JournalLock {
    fn drop(&mut self) {
        let _ = fs2::FileExt::unlock(&self.file);
    }
}

fn acquire_journal_lock(scope: &Path, private_root: &Path) -> Result<JournalLock, String> {
    let path = scope.join(JOURNAL_LOCK_FILE);
    #[cfg(windows)]
    let (file, directory_binding) =
        crate::resident_state::private_lock_file(&path, private_root)
            .map_err(|_| "native_resident_lifecycle_journal_lock_failed".to_owned())?;
    #[cfg(not(windows))]
    let file = crate::resident_state::private_lock_file(&path, private_root)
        .map_err(|_| "native_resident_lifecycle_journal_lock_failed".to_owned())?;
    fs2::FileExt::try_lock_exclusive(&file).map_err(|error| {
        if crate::resident_state::is_lock_contention(&error) {
            "native_resident_lifecycle_journal_busy".to_owned()
        } else {
            "native_resident_lifecycle_journal_lock_failed".to_owned()
        }
    })?;
    Ok(JournalLock {
        file,
        #[cfg(windows)]
        _directory_binding: directory_binding,
    })
}

fn acquire_journal_lock_waiting(scope: &Path, private_root: &Path) -> Result<JournalLock, String> {
    let mut attempts = 0;
    loop {
        match acquire_journal_lock(scope, private_root) {
            Err(reason) if reason == "native_resident_lifecycle_journal_busy" => {
                attempts += 1;
                if attempts > JOURNAL_LOCK_RETRIES {
                    return Err(reason);
                }
                std::thread::sleep(JOURNAL_LOCK_RETRY_DELAY);
            }
            other => return other,
        }
    }
}

fn now_ms() -> Result<u64, String> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| "native_resident_clock_invalid".to_owned())?
            .as_millis(),
    )
    .map_err(|_| "native_resident_clock_invalid".to_owned())
}

/// Read this scope's journal when it exists and is this module's own.
///
/// A file that fails to parse, or carries another schema, is treated as absent
/// rather than as an error to report: the journal is not authority, and the
/// next event rewrites it from an empty day. Discarding one damaged day's
/// counts is cheaper than letting a corrupt file stop the runtime recording
/// anything ever again. A file whose last event is not one of this module's
/// codes fails to parse for exactly that reason, so an edited vocabulary costs
/// the same day and reaches no reader.
fn read_existing(path: &Path, private_root: &Path) -> Option<Journal> {
    let bytes = read_private_bytes(path, private_root, "lifecycle_journal").ok()??;
    let value = crate::strict_json_value(&bytes).ok()?;
    let journal = serde_json::from_value::<Journal>(value).ok()?;
    if journal.schema != JOURNAL_SCHEMA {
        return None;
    }
    Some(journal)
}

fn load_for_window(path: &Path, private_root: &Path, now: u64) -> Journal {
    let mut journal = read_existing(path, private_root).unwrap_or_else(Journal::new);
    journal.retain_window(now);
    journal
}

/// Count one event against this install's day, waiting briefly for the lock.
///
/// Nothing is returned, and that is the point: every caller is on a path whose
/// result belongs to the runtime, not to the journal. This is the supervisor's
/// way in, where nobody is holding a deadline open behind the write.
pub(super) fn record(scope: &Path, event: Event) {
    let _ = record_at(scope, event, None, true);
}

/// Count one event without ever waiting for the lock.
///
/// The spawn path runs under a client's deadline. Sleeping on a contended
/// journal there could spend that deadline and still leave a resident started
/// for an answer the caller can no longer wait for, so a journal that is busy
/// at this moment loses the event instead.
pub(super) fn record_without_waiting(scope: &Path, event: Event) {
    let _ = record_at(scope, event, None, false);
}

/// Hold this install's journal lock, so a test can play out a caller that
/// arrives while a supervisor is already recording. The lock is released when
/// the returned value is dropped.
#[cfg(test)]
pub(super) fn lock_for_test(scope: &Path) -> impl Drop {
    let private_root =
        crate::resident_state::private_root_for_scope(scope).expect("a private root for the scope");
    acquire_journal_lock(scope, &private_root).expect("an uncontended journal lock")
}

fn record_at(
    scope: &Path,
    event: Event,
    at_ms: Option<u64>,
    wait_for_lock: bool,
) -> Result<(), String> {
    let private_root = crate::resident_state::private_root_for_scope(scope)?;
    let _lock = if wait_for_lock {
        acquire_journal_lock_waiting(scope, &private_root)?
    } else {
        acquire_journal_lock(scope, &private_root)?
    };
    let path = scope.join(JOURNAL_FILE);
    #[cfg(windows)]
    recover_interrupted_replace(&path, &private_root)?;
    let now = match at_ms {
        Some(simulated) => simulated,
        None => now_ms()?,
    };
    let mut journal = load_for_window(&path, &private_root, now);
    journal.apply(event, now);
    let encoded = serde_json::to_vec(&journal)
        .map_err(|_| "native_resident_lifecycle_journal_encode_failed".to_owned())?;
    write_private(&path, &encoded, &private_root)
}

/// How this install's resident has been behaving, or `None` when it has no
/// journal yet. A read takes the lock so it cannot catch a half-written file
/// on a platform where the replace is not atomic.
pub(super) fn health(scope: &Path) -> Result<Option<LifecycleHealth>, String> {
    let private_root = crate::resident_state::private_root_for_scope(scope)?;
    let _lock = acquire_journal_lock_waiting(scope, &private_root)?;
    let path = scope.join(JOURNAL_FILE);
    let now = now_ms()?;
    let Some(mut journal) = read_existing(&path, &private_root) else {
        return Ok(None);
    };
    journal.retain_window(now);
    let Some(oldest) = journal.hours.first() else {
        return Ok(None);
    };
    let window_start_ms = oldest.hour.saturating_mul(JOURNAL_BUCKET_MS);
    let totals = journal.totals();
    Ok(Some(LifecycleHealth {
        state: health_state(&journal, &totals),
        starts: totals.starts,
        orderly_exits: totals.orderly_exits,
        failed_exits: totals.failed_exits,
        premature_exits: totals.premature_exits,
        refused_starts: totals.refused_starts,
        last_event: journal.last_event.map_or("", Event::code),
        // A journal with no event left to name has no age to report either,
        // rather than the age of the epoch.
        last_event_age_seconds: match journal.last_event {
            Some(_) => now.saturating_sub(journal.last_event_ms) / 1_000,
            None => 0,
        },
        window_age_seconds: now.saturating_sub(window_start_ms) / 1_000,
    }))
}

/// How this install's managed resident has behaved over the last day, in the
/// counts this module keeps. `None` means this runtime has no history here
/// yet, which is what a fresh install and an install that has not run for a
/// day both look like.
///
/// This is the whole-install entry point, resolving the scope the way every
/// other managed-resident caller does; `health` takes a scope already in hand.
pub(crate) fn lifecycle_health(state_base: &Path) -> Result<Option<LifecycleHealth>, String> {
    let digest = super::runtime_digest()?;
    let scope = super::state_scope(state_base, &digest)?;
    health(&scope)
}

#[cfg(test)]
#[path = "resident_lifecycle_journal_tests.rs"]
mod tests;
