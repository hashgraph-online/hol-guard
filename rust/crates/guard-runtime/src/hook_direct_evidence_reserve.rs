//! A slot in the direct evidence queue promised before the step its receipt
//! explains.
//!
//! `has_headroom` is a check that hooks running at the same time share, so a
//! caller that writes a row only its receipt names could still find the queue
//! full once the row exists. A reservation holds one worst-case record against
//! every other offer until the caller spends it on that receipt or drops it.

use std::sync::{Arc, Mutex};

use serde_json::Value;

use super::{DirectEvidenceQueue, QueueState, MAX_RECORD_BYTES};

/// One worst-case record the queue keeps free for its holder. Dropping it
/// unspent returns the room.
pub(crate) struct Reserved(Option<Arc<Mutex<QueueState>>>);

impl DirectEvidenceQueue {
    /// Promise one worst-case record, or `None` when the queue cannot.
    pub(crate) fn reserve(&self) -> Option<Reserved> {
        let mut state = self.state.lock().ok()?;
        if !state.holds(MAX_RECORD_BYTES) {
            return None;
        }
        state.reserved += 1;
        Some(Reserved(Some(Arc::clone(&self.state))))
    }
}

impl Reserved {
    /// Queue the record into the promised room. Only a record larger than
    /// any the queue takes is refused.
    pub(crate) fn offer(mut self, record: Value) -> bool {
        let Some(queue) = self.0.take() else {
            return false;
        };
        let Ok(mut state) = queue.lock() else {
            return false;
        };
        state.reserved = state.reserved.saturating_sub(1);
        let Ok(encoded) = serde_json::to_vec(&record) else {
            return false;
        };
        let bytes = encoded.len();
        if bytes > MAX_RECORD_BYTES {
            return false;
        }
        let native = crate::mcp_relay_receipt::is_plain(&record);
        state.append(record, bytes, native, false);
        true
    }
}

impl Drop for Reserved {
    fn drop(&mut self) {
        if let Some(queue) = self.0.take() {
            if let Ok(mut state) = queue.lock() {
                state.reserved = state.reserved.saturating_sub(1);
            }
        }
    }
}

#[cfg(test)]
#[path = "hook_direct_evidence_reserve_tests.rs"]
mod tests;
