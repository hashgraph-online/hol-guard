//! `apply_review_memory`: `apply_review_policy_memory_state`, written by the
//! resident.
//!
//! The caller verifies the memory bundle and seals each decision. The
//! resident replaces the remote policy decisions with them and writes the
//! memory registry, policy version and acknowledgement in one transaction.

use std::cell::RefCell;

use guard_contracts::{ExtensionControlAuthorityRequestV1, ExtensionControlReviewMemoryV1};
use serde_json::{json, Value};

use super::policy_apply::row_values;
use super::records::{degraded, tampered, Res};
use super::resume::immediate;
use super::writes::open_writer;
use super::{fault_value, Ctx, STORE_UNAVAILABLE};

/// The `sync_state` keys a memory publish writes.
const PAYLOAD_KEYS: [&str; 3] = [
    "guard_review_memory_registry",
    "guard_review_memory_policy_version",
    "guard_review_memory_last_ack",
];
const INVALID: &str = "invalid review memory request";

pub(super) fn apply_review_memory_op(
    request: &ExtensionControlAuthorityRequestV1,
    key: Option<&[u8]>,
) -> Result<Value, String> {
    let Some(connection) = open_writer(request)? else {
        return Ok(fault_value(&degraded(STORE_UNAVAILABLE), Vec::new()));
    };
    let ctx = Ctx {
        connection: &connection,
        key,
        request,
        events: RefCell::new(Vec::new()),
    };
    Ok(ctx
        .apply_review_memory()
        .unwrap_or_else(|fault| fault_value(&fault, Vec::new())))
}

fn validate(memory: &ExtensionControlReviewMemoryV1) -> Res<()> {
    let payloads_valid = memory.payloads.len() == PAYLOAD_KEYS.len()
        && memory.payloads.iter().all(|(state_key, payload)| {
            // The registry is a list, the version and acknowledgement are
            // objects: a later sync reads them as such.
            matches!(
                (state_key.as_str(), serde_json::from_str::<Value>(payload)),
                ("guard_review_memory_registry", Ok(Value::Array(_)))
                    | (
                        "guard_review_memory_policy_version" | "guard_review_memory_last_ack",
                        Ok(Value::Object(_))
                    )
            )
        });
    if payloads_valid {
        Ok(())
    } else {
        Err(tampered(INVALID))
    }
}

impl Ctx<'_> {
    fn apply_review_memory(&self) -> Res<Value> {
        let memory = self
            .request
            .review_memory
            .as_ref()
            .ok_or_else(|| tampered(INVALID))?;
        let now = self
            .request
            .now
            .as_deref()
            .ok_or_else(|| tampered(INVALID))?;
        validate(memory)?;
        let rows = memory
            .rows
            .iter()
            .map(|row| row_values(row))
            .collect::<Res<Vec<_>>>()
            .map_err(|_| tampered(INVALID))?;
        immediate(self.connection, || {
            self.replace_remote_rows(&rows)?;
            self.write_sync_state(&memory.payloads, now)?;
            Ok(json!({ "applied": true }))
        })
    }
}

#[cfg(test)]
#[path = "review_memory_tests.rs"]
mod tests;
