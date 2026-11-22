#![forbid(unsafe_code)]

//! A store read that another install's resident predates, answered here.
//!
//! Two Guard installs can share one home, for example a CLI updated ahead of
//! the Desktop app's bundled runtime. The older install keeps the resident
//! while its own clients hold leases, so this client talks to a resident that
//! does not know the store methods added since. It answers those with
//! `native_guard_store_method_unknown`, and every command that needs one
//! fails until the other install updates too.
//!
//! A snapshot method reads several rows inside one deferred transaction and
//! always rolls it back, so it never writes and needs no resident state. This
//! client runs those with its own runtime instead. Every other method stays
//! with the resident: a plain read can still write (a pending rollup rebuild,
//! an expired pairing, outbox finalization), and the resident owns the outbox
//! wake-ups and write caches.

use std::time::Instant;

use guard_contracts::GuardStoreRequestV1;
use serde_json::Value;

use crate::guard_store_op_kind::{method_kind, Kind};

const STORE_OPERATION: &str = "guard_store";
const STORE_RESULT_SCHEMA: &str = "guard-store-result.v1";
const INVALID_CODE: &str = "native_guard_store_invalid";
const METHOD_UNKNOWN: &str = "native_guard_store_method_unknown";

/// `response` from a resident of another runtime, or this runtime's answer
/// when that resident did not know the snapshot read it was sent.
pub(super) fn reply(payload: &[u8], response: Vec<u8>, deadline: Instant) -> Vec<u8> {
    match answer_unknown_snapshot(payload, &response, deadline) {
        Some(answer) => {
            crate::resident_diagnostics::note("client_state_foreign_store_read_local", 1);
            answer
        }
        None => response,
    }
}

fn answer_unknown_snapshot(payload: &[u8], response: &[u8], deadline: Instant) -> Option<Vec<u8>> {
    if !reports_unknown_method(response) {
        return None;
    }
    let envelope = crate::strict_json_value(payload).ok()?;
    if envelope.get("operation").and_then(Value::as_str) != Some(STORE_OPERATION) {
        return None;
    }
    let request: GuardStoreRequestV1 =
        serde_json::from_value(envelope.get("request")?.clone()).ok()?;
    if method_kind(&request.method) != Some(Kind::Snapshot) {
        return None;
    }
    // The caller's digest covers the request as sent; the local busy wait
    // only gets the time that discovery and the resident exchange left.
    let request_sha256 = crate::guard_store_op::request_digest(&request).ok()?;
    let left_ms = u64::try_from(
        deadline
            .saturating_duration_since(Instant::now())
            .as_millis(),
    )
    .unwrap_or(u64::MAX);
    if left_ms == 0 {
        return None;
    }
    let bounded = GuardStoreRequestV1 {
        busy_timeout_ms: request.busy_timeout_ms.min(left_ms),
        ..request
    };
    let answer =
        crate::guard_store_op::evaluate_guard_store_request_with_owner(&bounded, None).ok()?;
    let mut answer = crate::strict_json_value(&answer).ok()?;
    answer
        .as_object_mut()?
        .insert("request_sha256".to_owned(), Value::from(request_sha256));
    serde_json::to_vec(&answer).ok()
}

fn reports_unknown_method(response: &[u8]) -> bool {
    crate::strict_json_value(response).is_ok_and(|response| {
        response.get("schema").and_then(Value::as_str) == Some(STORE_RESULT_SCHEMA)
            && response.get("status").and_then(Value::as_str) == Some("error")
            && response.get("code").and_then(Value::as_str) == Some(INVALID_CODE)
            && response
                .get("payload")
                .and_then(|payload| payload.get("message"))
                .and_then(Value::as_str)
                == Some(METHOD_UNKNOWN)
    })
}

#[cfg(test)]
#[path = "managed_resident_store_fallback_tests.rs"]
mod tests;
