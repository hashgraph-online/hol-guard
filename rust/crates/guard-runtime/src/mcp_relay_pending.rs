//! Forward evidence the resident holds until the relay completes the forward.
//!
//! The Python proxy records a forwarded `tools/call` only after the child
//! answered it. A call it decided to forward but then did not (the catalog
//! changed before the write) leaves no allow receipt. The resident therefore
//! holds a forward's evidence under a ticket, and the relay commits that
//! ticket once the child responded. Only a committed record reaches the
//! daemon's drain; a ticket the relay never commits (a boundary change, a
//! decision answer that never arrived, a relay that exited) expires here.
//! A commit the full drain refuses keeps the record held under its ticket,
//! and the relay commits that ticket again after a later forward.
//!
//! A ticket names this resident's epoch, so a commit sent to a restarted
//! resident releases nothing, and each ticket releases its record once.
//!
//! Gaps remain against the proxy. At a catalog boundary change the proxy
//! re-resolves the call and records a fresh block or approval receipt, while
//! the relay records nothing for it. A resident restart between the decision
//! and the commit drops the held record, as does a drain that stays full
//! past the hold's TTL or past the relay's bounded retry list.

use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::hook_direct_evidence::{DirectEvidenceQueue, MAX_RECORD_BYTES};

pub(crate) const COMMIT_RESULT_SCHEMA: &str = "guard-mcp-relay-commit-result.v1";
/// Forwards awaiting their commit; a decision without a free slot defers.
const MAX_HELD_RECORDS: usize = 256;
/// A forwarded tool may run long; its evidence waits this long for the commit.
const HOLD_TTL: Duration = Duration::from_secs(3_600);

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct McpRelayCommitRequestV1 {
    pub(crate) guard_home: String,
    pub(crate) ticket: String,
}

struct Held {
    seq: u64,
    held_at: Instant,
    record: Value,
}

struct HeldState {
    next_seq: u64,
    records: VecDeque<Held>,
    /// Slots promised to decisions that write rows before their forward is
    /// held (see `reserve`).
    reserved: usize,
}

impl HeldState {
    fn expire(&mut self, now: Instant) {
        self.records
            .retain(|held| now.saturating_duration_since(held.held_at) < HOLD_TTL);
    }

    fn push(&mut self, epoch: &str, record: Value, now: Instant) -> String {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        self.records.push_back(Held {
            seq,
            held_at: now,
            record,
        });
        format!("{epoch}:{seq}")
    }
}

pub(crate) struct PendingRelayEvidence {
    epoch: String,
    state: Mutex<HeldState>,
}

impl Default for PendingRelayEvidence {
    fn default() -> Self {
        static HOLDS: AtomicU64 = AtomicU64::new(0);
        let started = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or_default();
        Self {
            epoch: format!(
                "{:x}-{started:x}-{:x}",
                std::process::id(),
                HOLDS.fetch_add(1, Ordering::Relaxed)
            ),
            state: Mutex::new(HeldState {
                next_seq: 1,
                records: VecDeque::new(),
                reserved: 0,
            }),
        }
    }
}

impl PendingRelayEvidence {
    /// Whether a forward can reserve a held-record slot before it performs a
    /// remembered policy write.
    pub(crate) fn has_headroom(&self, now: Instant) -> bool {
        let Ok(mut state) = self.state.lock() else {
            return false;
        };
        state
            .records
            .retain(|held| now.saturating_duration_since(held.held_at) < HOLD_TTL);
        state.records.len() < MAX_HELD_RECORDS
    }

    /// Hold one forward's record; `None` when it cannot be held.
    pub(crate) fn hold(&self, record: Value, now: Instant) -> Option<String> {
        let bytes = serde_json::to_vec(&record).ok()?.len();
        if bytes > MAX_RECORD_BYTES {
            return None;
        }
        let mut state = self.state.lock().ok()?;
        state.expire(now);
        if state.records.len() + state.reserved >= MAX_HELD_RECORDS {
            return None;
        }
        Some(state.push(&self.epoch, record, now))
    }

    /// Promise one held slot to a decision that writes rows its forward's
    /// record names, so a hold refused after those rows exist cannot happen;
    /// `None` when no slot is free.
    pub(crate) fn reserve(&self, now: Instant) -> Option<PendingSlot<'_>> {
        let mut state = self.state.lock().ok()?;
        state.expire(now);
        if state.records.len() + state.reserved >= MAX_HELD_RECORDS {
            return None;
        }
        state.reserved += 1;
        Some(PendingSlot(Some(self)))
    }

    /// Move a ticket's record to the drain; a refused record stays held.
    pub(crate) fn commit_into(
        &self,
        ticket: &str,
        queue: &DirectEvidenceQueue,
        now: Instant,
    ) -> Commit {
        let Some(seq) = self.sequence(ticket) else {
            return Commit::Unknown;
        };
        let Ok(mut state) = self.state.lock() else {
            return Commit::Unknown;
        };
        let Some(index) = state.records.iter().position(|held| held.seq == seq) else {
            return Commit::Unknown;
        };
        let Some(held) = state.records.remove(index) else {
            return Commit::Unknown;
        };
        if now.saturating_duration_since(held.held_at) >= HOLD_TTL {
            return Commit::Unknown;
        }
        match queue.try_offer(held.record) {
            Ok(()) => Commit::Committed,
            // The call ran: keep its record, in place and still TTL-bounded,
            // for the relay to commit again once the drain made room.
            Err(record) => {
                state.records.insert(
                    index,
                    Held {
                        seq: held.seq,
                        held_at: held.held_at,
                        record,
                    },
                );
                Commit::Retained
            }
        }
    }

    fn sequence(&self, ticket: &str) -> Option<u64> {
        ticket
            .strip_prefix(self.epoch.as_str())?
            .strip_prefix(':')?
            .parse::<u64>()
            .ok()
    }
}

/// One held slot promised by `reserve`; dropping it unspent returns it.
pub(crate) struct PendingSlot<'a>(Option<&'a PendingRelayEvidence>);

impl PendingSlot<'_> {
    /// Hold the forward's record in the promised slot. Only a record larger
    /// than any the drain takes is refused.
    pub(crate) fn hold(mut self, record: Value, now: Instant) -> Option<String> {
        let pending = self.0.take()?;
        let mut state = pending.state.lock().ok()?;
        state.reserved = state.reserved.saturating_sub(1);
        let bytes = serde_json::to_vec(&record).ok()?.len();
        if bytes > MAX_RECORD_BYTES {
            return None;
        }
        Some(state.push(&pending.epoch, record, now))
    }
}

impl Drop for PendingSlot<'_> {
    fn drop(&mut self) {
        if let Some(pending) = self.0.take() {
            if let Ok(mut state) = pending.state.lock() {
                state.reserved = state.reserved.saturating_sub(1);
            }
        }
    }
}

/// What one commit did with a ticket's record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Commit {
    /// The record reached the drain.
    Committed,
    /// The drain was full; the record stays held under the same ticket.
    Retained,
    /// No record: a foreign, expired, malformed or already used ticket.
    Unknown,
}

/// Queue a completed forward's evidence for the daemon's drain.
pub(crate) fn commit(
    request: &McpRelayCommitRequestV1,
    pending: &PendingRelayEvidence,
    queue: &DirectEvidenceQueue,
) -> Result<Vec<u8>, String> {
    let outcome = pending.commit_into(&request.ticket, queue, Instant::now());
    serde_json::to_vec(&json!({
        "schema": COMMIT_RESULT_SCHEMA,
        "committed": outcome == Commit::Committed,
        "retained": outcome == Commit::Retained,
    }))
    .map_err(|_| "mcp_relay_commit_result_encoding_failed".to_owned())
}

#[cfg(test)]
#[path = "mcp_relay_pending_tests.rs"]
mod tests;
