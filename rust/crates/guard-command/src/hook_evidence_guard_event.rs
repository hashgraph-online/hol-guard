//! A timeline event queued with the hook evidence.
//!
//! The writer saves it to the local event log, as `GuardStore.add_event`
//! does. It takes only the events named here, so a journal entry cannot put
//! any other event into the log.

use serde_json::{json, Map, Value};

use super::{
    _timestamp_is_utc_aware, uuid4_hex, write_canonical_json_with_limit,
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
