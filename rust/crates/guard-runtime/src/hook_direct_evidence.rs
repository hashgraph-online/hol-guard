//! Evidence for hooks the resident answers directly.
//!
//! After a `PreToolUse` allow the daemon records the decision receipt and the
//! command activity, and observes the command line. A direct answer skips the
//! daemon, so the resident keeps those inputs here until the daemon drains
//! them over the resident channel and records them through its own writer.
//!
//! The queue lives in memory only, so raw tool input never reaches disk
//! outside the daemon's evidence writer. A record that does not fit makes the
//! hook take the daemon path rather than answer without its evidence. A page
//! stays queued until the daemon acknowledges its cursor, so a lost response
//! is sent again. Each queue names its own epoch, and an acknowledgement from
//! another epoch is ignored: a restarted resident numbers its records from
//! one again, and the daemon's cursor for the old resident must not drop them.
//! Each page also carries the queue's diagnostic hook counts, which the
//! daemon only logs.

use crate::hook_direct_counters::DirectHookCounters;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) const HOOK_DIRECT_EVIDENCE_FEATURE: &str = "hook-direct-evidence-v1";
const DRAIN_RESULT_SCHEMA: &str = "guard-hook-direct-evidence.v1";
const MAX_QUEUED_RECORDS: usize = 1_024;
const MAX_QUEUED_BYTES: usize = 8 * 1024 * 1024;
/// One drain page stays well under the resident response cap.
const MAX_DRAIN_BYTES: usize = 1536 * 1024;
pub(crate) const MAX_RECORD_BYTES: usize = 1024 * 1024;
const DEFAULT_DRAIN_RECORDS: usize = 256;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct HookDirectEvidenceDrainRequestV1 {
    pub(crate) guard_home: String,
    #[serde(default)]
    pub(crate) max_records: Option<usize>,
    /// Drop queued records through this cursor. Absent on the first page.
    #[serde(default)]
    pub(crate) ack_through: Option<u64>,
    /// The epoch of the page that `ack_through` acknowledges.
    #[serde(default)]
    pub(crate) ack_epoch: Option<String>,
}

struct QueuedRecord {
    seq: u64,
    bytes: usize,
    record: Value,
}

struct QueueState {
    records: VecDeque<QueuedRecord>,
    bytes: usize,
    next_seq: u64,
    acked_through: u64,
}

impl Default for QueueState {
    fn default() -> Self {
        Self {
            records: VecDeque::new(),
            bytes: 0,
            next_seq: 1,
            acked_through: 0,
        }
    }
}

pub(crate) struct DirectEvidenceQueue {
    epoch: String,
    state: Mutex<QueueState>,
    counters: DirectHookCounters,
}

impl Default for DirectEvidenceQueue {
    fn default() -> Self {
        static QUEUES: AtomicU64 = AtomicU64::new(0);
        let started = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_nanos())
            .unwrap_or_default();
        Self {
            epoch: format!(
                "{:x}-{started:x}-{:x}",
                std::process::id(),
                QUEUES.fetch_add(1, Ordering::Relaxed)
            ),
            state: Mutex::new(QueueState::default()),
            counters: DirectHookCounters::default(),
        }
    }
}

impl DirectEvidenceQueue {
    /// The diagnostic counts of direct hooks since this queue started.
    pub(crate) fn counters(&self) -> &DirectHookCounters {
        &self.counters
    }

    /// Queue one record, or refuse it when the queue cannot hold it.
    pub(crate) fn offer(&self, record: Value) -> bool {
        self.try_offer(record).is_ok()
    }

    /// Queue one record, or hand it back when the queue cannot hold it.
    pub(crate) fn try_offer(&self, record: Value) -> Result<(), Value> {
        let Ok(encoded) = serde_json::to_vec(&record) else {
            return Err(record);
        };
        let bytes = encoded.len();
        if bytes > MAX_RECORD_BYTES {
            return Err(record);
        }
        let Ok(mut state) = self.state.lock() else {
            return Err(record);
        };
        if state.records.len() >= MAX_QUEUED_RECORDS || state.bytes + bytes > MAX_QUEUED_BYTES {
            return Err(record);
        }
        let seq = state.next_seq;
        state.next_seq = state.next_seq.saturating_add(1);
        state.bytes += bytes;
        state.records.push_back(QueuedRecord { seq, bytes, record });
        Ok(())
    }

    /// Acknowledge records the daemon already has, then copy the next page.
    ///
    /// Unacknowledged records stay queued. A lost response is therefore sent
    /// again instead of dropping evidence for an allow that already returned.
    fn acknowledge_and_peek(
        &self,
        ack_through: Option<u64>,
        ack_epoch: Option<&str>,
        max_records: usize,
    ) -> (Vec<Value>, usize, Option<u64>) {
        let Ok(mut state) = self.state.lock() else {
            return (Vec::new(), 0, None);
        };
        let ack = ack_through.filter(|_| ack_epoch == Some(self.epoch.as_str()));
        if let Some(ack) = ack {
            if ack >= state.acked_through {
                state.acked_through = ack;
                while state
                    .records
                    .front()
                    .map(|next| next.seq <= ack)
                    .unwrap_or(false)
                {
                    let Some(next) = state.records.pop_front() else {
                        break;
                    };
                    state.bytes -= next.bytes;
                }
            }
        }
        let mut taken = Vec::new();
        let mut page_bytes = 0;
        let mut through = None;
        for next in &state.records {
            if taken.len() >= max_records {
                break;
            }
            if !taken.is_empty() && page_bytes + next.bytes > MAX_DRAIN_BYTES {
                break;
            }
            page_bytes += next.bytes;
            through = Some(next.seq);
            taken.push(next.record.clone());
        }
        let remaining = state.records.len().saturating_sub(taken.len());
        (taken, remaining, through)
    }
}

pub(crate) fn drain(
    request: &HookDirectEvidenceDrainRequestV1,
    queue: &DirectEvidenceQueue,
) -> Result<Vec<u8>, String> {
    let max_records = request
        .max_records
        .unwrap_or(DEFAULT_DRAIN_RECORDS)
        .clamp(1, DEFAULT_DRAIN_RECORDS);
    let (records, remaining, through) = queue.acknowledge_and_peek(
        request.ack_through,
        request.ack_epoch.as_deref(),
        max_records,
    );
    serde_json::to_vec(&json!({
        "schema": DRAIN_RESULT_SCHEMA,
        "epoch": queue.epoch,
        "records": records,
        "remaining": remaining,
        "through": through,
        "counters": queue.counters.snapshot(),
    }))
    .map_err(|_| "direct_hook_evidence_encoding_failed".to_owned())
}

#[cfg(test)]
#[path = "hook_direct_evidence_tests.rs"]
mod tests;
