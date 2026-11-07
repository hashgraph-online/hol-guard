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
//!
//! A paged record that carries a decision receipt also says whether the
//! receipt is one the native runtime accepts, checked here as the daemon's
//! own validation request would check it, so the daemon records it without
//! another resident request per hook.
//!
//! A plain relayed MCP call's record is never paged: the page's cursor passes
//! over it, and once the daemon acknowledges that cursor the resident writes
//! the call's receipt itself (see [`crate::mcp_relay_receipt`]). A receipt the
//! store cannot take goes back on the queue as an ordinary record, so the
//! daemon records it as it did before.
//!
//! A paged record whose receipt the resident has not written yet is recorded
//! before the page leaves, as the `record` module describes.

use crate::hook_direct_counters::DirectHookCounters;
use serde::Deserialize;
use serde_json::{json, Value};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

pub(crate) const HOOK_DIRECT_EVIDENCE_FEATURE: &str = "hook-direct-evidence-v1";
const DRAIN_RESULT_SCHEMA: &str = "guard-hook-direct-evidence.v1";
/// The field of a paged record that says whether its `receipt` is valid.
const RECEIPT_VALID: &str = "receipt_valid";
const MAX_QUEUED_RECORDS: usize = 1_024;
const MAX_QUEUED_BYTES: usize = 8 * 1024 * 1024;
/// One drain page stays well under the resident response cap.
const MAX_DRAIN_BYTES: usize = 1536 * 1024;
pub(crate) const MAX_RECORD_BYTES: usize = 1024 * 1024;
const DEFAULT_DRAIN_RECORDS: usize = 256;
/// The records [`DirectEvidenceQueue::has_headroom`] keeps free for hooks
/// that run concurrently with the one asking.
const HEADROOM_RECORDS: usize = 64;

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
    /// The resident writes this record's receipt itself, after the ack.
    native: bool,
    /// The bound daemon let the resident record this answer's activity.
    activity: bool,
}

/// A queued record copied onto a page.
struct Paged {
    seq: u64,
    record: Value,
    activity: bool,
}

/// What one drain request takes from the queue.
struct Peeked {
    records: Vec<Paged>,
    remaining: usize,
    through: Option<u64>,
    /// Acknowledged records whose receipts the resident writes.
    settled: Vec<Value>,
}

struct QueueState {
    records: VecDeque<QueuedRecord>,
    bytes: usize,
    next_seq: u64,
    acked_through: u64,
}

impl QueueState {
    /// Queue one encoded record, or hand it back when the queue is full.
    fn push(
        &mut self,
        record: Value,
        bytes: usize,
        native: bool,
        activity: bool,
    ) -> Result<(), Value> {
        if !self.holds(bytes) {
            return Err(record);
        }
        self.append(record, bytes, native, activity);
        Ok(())
    }

    fn holds(&self, bytes: usize) -> bool {
        self.records.len() < MAX_QUEUED_RECORDS && self.bytes + bytes <= MAX_QUEUED_BYTES
    }

    /// Queue one encoded record past the queue's limits.
    fn append(&mut self, record: Value, bytes: usize, native: bool, activity: bool) {
        let seq = self.next_seq;
        self.next_seq = self.next_seq.saturating_add(1);
        self.bytes += bytes;
        self.records.push_back(QueuedRecord {
            seq,
            bytes,
            record,
            native,
            activity,
        });
    }

    /// Add `markers` to the queued record `seq`, if it is still queued.
    fn mark(&mut self, seq: u64, markers: &[&str]) {
        let Some(queued) = self.records.iter_mut().find(|queued| queued.seq == seq) else {
            return;
        };
        let Some(fields) = queued.record.as_object_mut() else {
            return;
        };
        for marker in markers {
            fields.insert((*marker).to_owned(), Value::Bool(true));
        }
        let bytes =
            serde_json::to_vec(&queued.record).map_or(queued.bytes, |encoded| encoded.len());
        self.bytes = (self.bytes - queued.bytes).saturating_add(bytes);
        queued.bytes = bytes;
    }
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

fn unmarked(mut record: Value, markers: &[&str]) -> Value {
    if let Some(fields) = record.as_object_mut() {
        for marker in markers {
            fields.remove(*marker);
        }
    }
    record
}

pub(crate) struct DirectEvidenceQueue {
    epoch: String,
    state: Arc<Mutex<QueueState>>,
    counters: DirectHookCounters,
    /// Held while a drain records a page, so two drains never record the
    /// same record's activity, which the writer does not dedupe.
    recording: Mutex<()>,
}

/// Returns acknowledged records whose receipts the resident could not write
/// to their queue, as records the daemon drains and records itself.
#[derive(Clone)]
pub(crate) struct Unwritten(Arc<Mutex<QueueState>>);

impl Unwritten {
    pub(crate) fn requeue(&self, records: Vec<Value>) {
        if records.is_empty() {
            return;
        }
        let Ok(mut state) = self.0.lock() else {
            return;
        };
        // These records left the queue with the ack that settled them, so
        // nothing else holds them: they go back even past the queue's limits,
        // which they already counted against. They return as daemon records
        // and are never settled again, so the queue holds at most its limits
        // plus one acknowledged run.
        for record in records {
            let Ok(encoded) = serde_json::to_vec(&record) else {
                continue;
            };
            state.append(record, encoded.len(), false, false);
        }
    }
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
            state: Arc::new(Mutex::new(QueueState::default())),
            counters: DirectHookCounters::default(),
            recording: Mutex::new(()),
        }
    }
}

impl DirectEvidenceQueue {
    /// The diagnostic counts of direct hooks since this queue started.
    pub(crate) fn counters(&self) -> &DirectHookCounters {
        &self.counters
    }

    /// Whether a worst-case record still fits with room to spare. A hook
    /// about to take a step the daemon would repeat if the hook were handed
    /// back asks this first, so a full queue defers before that step and not
    /// after it. It is a check, not a reservation: hooks running at the same
    /// time share the spare room.
    pub(crate) fn has_headroom(&self) -> bool {
        let Ok(state) = self.state.lock() else {
            return false;
        };
        state.records.len() + HEADROOM_RECORDS <= MAX_QUEUED_RECORDS
            && state.bytes + 2 * MAX_RECORD_BYTES <= MAX_QUEUED_BYTES
    }

    /// Queue one record, or refuse it when the queue cannot hold it.
    pub(crate) fn offer(&self, record: Value) -> bool {
        self.try_offer(record).is_ok()
    }

    /// Queue a direct answer's record, which the drain records with
    /// `activity` as the bound daemon allowed it, or refuse it when the queue
    /// cannot hold it.
    pub(crate) fn offer_answer(&self, record: Value, activity: bool) -> bool {
        self.try_offer_with(record, activity).is_ok()
    }

    /// Queue one record, or hand it back when the queue cannot hold it.
    pub(crate) fn try_offer(&self, record: Value) -> Result<(), Value> {
        self.try_offer_with(record, false)
    }

    fn try_offer_with(&self, record: Value, activity: bool) -> Result<(), Value> {
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
        let native = crate::mcp_relay_receipt::is_plain(&record);
        state.push(record, bytes, native, activity)
    }

    /// Where the resident returns receipts it could not write.
    pub(crate) fn unwritten(&self) -> Unwritten {
        Unwritten(Arc::clone(&self.state))
    }

    /// Queue one record, marking it with each leading marker in `markers`
    /// whose evidence `record_evidence` records first, in order; hand it back
    /// when the queue cannot hold it.
    ///
    /// `record_evidence` reads the record and says how many of its markers it
    /// recorded. The room check, the writes and the push share one lock, so
    /// evidence is recorded only for a record the queue takes. A marker goes
    /// when its write is refused or the marked record would not fit; the
    /// drain then submits that evidence itself, which the writer dedupes for a
    /// receipt. The drain records this answer's activity only with `activity`.
    pub(crate) fn try_offer_recorded(
        &self,
        mut record: Value,
        markers: &[&str],
        activity: bool,
        record_evidence: impl FnOnce(&Value) -> usize,
    ) -> Result<(), Value> {
        let Ok(encoded) = serde_json::to_vec(&record) else {
            return Err(record);
        };
        let bytes = encoded.len();
        if bytes > MAX_RECORD_BYTES {
            return Err(record);
        }
        let Some(fields) = record.as_object_mut() else {
            return Err(record);
        };
        for marker in markers {
            fields.insert((*marker).to_owned(), Value::Bool(true));
        }
        let marked_bytes = serde_json::to_vec(&record).map_or(usize::MAX, |encoded| encoded.len());
        let Ok(mut state) = self.state.lock() else {
            return Err(unmarked(record, markers));
        };
        if !state.holds(bytes) {
            return Err(unmarked(record, markers));
        }
        let recorded = if marked_bytes <= MAX_RECORD_BYTES && state.holds(marked_bytes) {
            record_evidence(&record).min(markers.len())
        } else {
            0
        };
        if recorded > 0 {
            // Its receipt is already written. The queue holds the record
            // without the markers left to the drain, so it is charged for
            // that encoding, which is no larger than the marked one.
            let record = unmarked(record, &markers[recorded..]);
            let kept_bytes =
                serde_json::to_vec(&record).map_or(marked_bytes, |encoded| encoded.len());
            state.append(record, kept_bytes, false, activity);
        } else {
            let record = unmarked(record, markers);
            let native = crate::mcp_relay_receipt::is_plain(&record);
            state.append(record, bytes, native, activity);
        }
        Ok(())
    }

    /// Acknowledge records the daemon already has, then copy the next page.
    ///
    /// Unacknowledged records stay queued. A lost response is therefore sent
    /// again instead of dropping evidence for an allow that already returned.
    /// The page's cursor passes over the resident's own records, which leave
    /// the queue with the acknowledgement that covers them.
    fn acknowledge_and_peek(
        &self,
        ack_through: Option<u64>,
        ack_epoch: Option<&str>,
        max_records: usize,
    ) -> Peeked {
        let mut settled = Vec::new();
        let Ok(mut state) = self.state.lock() else {
            return Peeked {
                records: Vec::new(),
                remaining: 0,
                through: None,
                settled,
            };
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
                    if next.native {
                        settled.push(next.record);
                    }
                }
            }
        }
        // Only records the daemon receives count toward its page, so a run of
        // the resident's own records never yields an empty page with more
        // queued behind it: the queue's own bound limits the scan.
        let mut taken = Vec::new();
        let mut scanned = 0;
        let mut page_bytes = 0;
        let mut through = None;
        for next in &state.records {
            if taken.len() >= max_records {
                break;
            }
            if !next.native {
                if !taken.is_empty() && page_bytes + next.bytes > MAX_DRAIN_BYTES {
                    break;
                }
                page_bytes += next.bytes;
                taken.push(Paged {
                    seq: next.seq,
                    record: next.record.clone(),
                    activity: next.activity,
                });
            }
            scanned += 1;
            through = Some(next.seq);
        }
        Peeked {
            records: taken,
            remaining: state.records.len().saturating_sub(scanned),
            through,
            settled,
        }
    }
}

pub(crate) fn drain(
    request: &HookDirectEvidenceDrainRequestV1,
    queue: &DirectEvidenceQueue,
    writer_source: Option<&str>,
) -> Result<Vec<u8>, String> {
    let max_records = request
        .max_records
        .unwrap_or(DEFAULT_DRAIN_RECORDS)
        .clamp(1, DEFAULT_DRAIN_RECORDS);
    let recording = queue
        .recording
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let peeked = queue.acknowledge_and_peek(
        request.ack_through,
        request.ack_epoch.as_deref(),
        max_records,
    );
    crate::mcp_relay_receipt::write_detached(
        &request.guard_home,
        peeked.settled,
        queue.unwritten(),
    );
    let mut paged: Vec<Paged> = peeked
        .records
        .into_iter()
        .map(|paged| Paged {
            record: checked_receipt(paged.record),
            ..paged
        })
        .collect();
    let store_fatal = writer_source
        .filter(|_| !request.guard_home.is_empty())
        .and_then(|source| record::leftovers(queue, &request.guard_home, source, &mut paged));
    drop(recording);
    let records: Vec<Value> = paged.into_iter().map(|paged| paged.record).collect();
    let mut page = json!({
        "schema": DRAIN_RESULT_SCHEMA,
        "epoch": queue.epoch,
        "records": records,
        "remaining": peeked.remaining,
        "through": peeked.through,
        "counters": queue.counters.snapshot(),
    });
    if let Some(fatal) = store_fatal.filter(|fatal| !fatal.is_null()) {
        // The daemon recovers its store from this, as from a writer reply.
        page["store_fatal"] = fatal;
    }
    serde_json::to_vec(&page).map_err(|_| "direct_hook_evidence_encoding_failed".to_owned())
}

/// `record`, marked with whether the receipt it carries is one the native
/// runtime accepts. A record without a receipt object is paged as queued.
fn checked_receipt(mut record: Value) -> Value {
    let valid = record
        .get("receipt")
        .filter(|receipt| receipt.is_object())
        .map(|receipt| crate::edge::standalone_receipt(receipt, &Value::Null));
    if let (Some(valid), Some(fields)) = (valid, record.as_object_mut()) {
        fields.insert(RECEIPT_VALID.to_owned(), Value::Bool(valid));
    }
    record
}

#[path = "hook_direct_evidence_notice.rs"]
mod notice;
#[path = "hook_direct_evidence_record.rs"]
mod record;
#[cfg(test)]
#[path = "hook_direct_evidence_tests.rs"]
mod tests;
