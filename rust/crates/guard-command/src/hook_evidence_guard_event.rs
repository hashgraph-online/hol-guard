//! A timeline event queued with the hook evidence.
//!
//! The writer saves it to the local event log, as `GuardStore.add_event`
//! does. It takes only the events named here, so a journal entry cannot put
//! any other event into the log.

use std::num::NonZeroU32;

use serde_json::{json, Map, Value};

use super::{
    _timestamp_is_utc_aware, store_refused, uuid4_hex, write_canonical_json_with_limit,
    EvidenceRecord, EvidenceWorker, PersistOutcome, RuntimeHookEvidenceWriter,
    MAX_SERIALIZED_RECORD_BYTES, SAFE_IDENTIFIER,
};

/// The journal envelope of a queued event.
pub(super) const GUARD_EVENT_SCHEMA: &str = "hol-guard-runtime-guard-event.v1";
/// `hook_policy_fence_window.POLICY_SOURCE_FENCE_WINDOW_EVENT`: a hook held
/// while a policy update owned the business-source fence.
pub const POLICY_SOURCE_FENCE_WINDOW_EVENT: &str = "policy_source_fence_window";
const EVENT_NAMES: [&str; 1] = [POLICY_SOURCE_FENCE_WINDOW_EVENT];
/// The largest payload one event carries, encoded.
const MAX_PAYLOAD_BYTES: usize = 4096;

#[derive(Debug, Clone)]
pub struct GuardEventRecord {
    pub record_id: String,
    pub event_name: String,
    pub payload: Map<String, Value>,
    pub occurred_at: String,
    pub payload_bytes: usize,
}

impl GuardEventRecord {
    /// A new record, or `None` for an event this writer does not take.
    pub(super) fn new(
        event_name: &str,
        payload: Map<String, Value>,
        occurred_at: &str,
    ) -> Option<Self> {
        Self {
            record_id: uuid4_hex(),
            event_name: event_name.to_owned(),
            payload,
            occurred_at: occurred_at.to_owned(),
            payload_bytes: 0,
        }
        .checked()
    }

    fn checked(mut self) -> Option<Self> {
        let payload_fits = serde_json::to_vec(&self.payload)
            .is_ok_and(|encoded| encoded.len() <= MAX_PAYLOAD_BYTES);
        if !EVENT_NAMES.contains(&self.event_name.as_str())
            || !SAFE_IDENTIFIER.is_match(&self.record_id)
            || !_timestamp_is_utc_aware(&self.occurred_at)
            || !payload_fits
        {
            return None;
        }
        self.payload_bytes = self.serialized().len();
        Some(self)
    }

    /// Sorted compact ASCII JSON and a newline, as the other records.
    pub fn serialized(&self) -> Vec<u8> {
        let payload = json!({
            "schema": GUARD_EVENT_SCHEMA,
            "record_id": self.record_id,
            "event_name": self.event_name,
            "payload": self.payload,
            "occurred_at": self.occurred_at,
        });
        let mut encoded = Vec::new();
        if write_canonical_json_with_limit(
            &payload,
            &mut encoded,
            MAX_SERIALIZED_RECORD_BYTES,
            "record too large",
        )
        .is_err()
        {
            encoded = serde_json::to_vec(&payload).unwrap_or_default();
        }
        encoded.push(b'\n');
        encoded
    }

    /// The record a journal line holds, checked as a new one is.
    pub(super) fn from_json(value: &Map<String, Value>) -> Option<Self> {
        if value.len() != 5 || value.get("schema") != Some(&json!(GUARD_EVENT_SCHEMA)) {
            return None;
        }
        Self {
            record_id: value.get("record_id")?.as_str()?.to_owned(),
            event_name: value.get("event_name")?.as_str()?.to_owned(),
            payload: value.get("payload")?.as_object()?.clone(),
            occurred_at: value.get("occurred_at")?.as_str()?.to_owned(),
            payload_bytes: 0,
        }
        .checked()
    }
}

impl RuntimeHookEvidenceWriter {
    /// Queue a timeline event for the local event log. False when the event
    /// is not one this writer takes or the queue is full.
    pub fn submit_guard_event(
        &self,
        event_name: &str,
        payload: Map<String, Value>,
        occurred_at: &str,
    ) -> bool {
        let Some(record) = GuardEventRecord::new(event_name, payload, occurred_at) else {
            return false;
        };
        let record = EvidenceRecord::GuardEvent(record);
        let mut state = self.lock_state();
        if state.stopping
            || state.records.len() >= self.max_records
            || state.queued_bytes + record.payload_bytes() > self.max_bytes
        {
            state.dropped += 1;
            state.degraded = true;
            return false;
        }
        state.queued_bytes += record.payload_bytes();
        state.records.push_back(record);
        state.accepted += 1;
        self.condition.1.notify_one();
        true
    }
}

impl EvidenceWorker {
    /// Save a queued timeline event to the local event log.
    pub(super) fn persist_guard_event(&self, record: &GuardEventRecord) -> PersistOutcome {
        let _timeout_guard = self.deps.sqlite_timeout.sqlite_timeout_override(
            NonZeroU32::new((self.sqlite_timeout_seconds * 1000.0).ceil().max(1.0) as u32)
                .unwrap_or(NonZeroU32::MIN),
        );
        match self.store.record_guard_event(
            &record.event_name,
            &record.payload,
            &record.occurred_at,
        ) {
            Ok(()) => PersistOutcome::Done,
            Err(error) => store_refused(&error),
        }
    }
}
