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
//! A store read is one SQLite transaction over `guard.db` with no resident
//! state behind it, so this client runs it with its own runtime instead. Only
//! methods this runtime classifies as a read or snapshot are answered, less
//! the few read-kind methods that take the write lock themselves: a write
//! stays with the resident, which owns the outbox wake-ups and write caches.

use guard_contracts::GuardStoreRequestV1;
use serde_json::Value;

use crate::guard_store_op_kind::{method_kind, Kind};

const STORE_OPERATION: &str = "guard_store";
const STORE_RESULT_SCHEMA: &str = "guard-store-result.v1";
const INVALID_CODE: &str = "native_guard_store_invalid";
const METHOD_UNKNOWN: &str = "native_guard_store_method_unknown";
/// Read-kind methods that take the write lock themselves (see
/// `guard_store_op_kind.rs`). Only a resident answers them.
const WRITES_ON_ITS_OWN: [&str; 6] = [
    "settle_claimed_native_allow",
    "settle_claimed_native_review",
    "codex_live_allow_authority",
    "complete_codex_live_decision",
    "record_codex_live_completion",
    "run_storage_housekeeping",
];

/// `response`, or this runtime's answer when a resident of another runtime
/// did not know the store read it was sent.
pub(super) fn reply(payload: &[u8], response: Vec<u8>, same_runtime: bool) -> Vec<u8> {
    if same_runtime {
        return response;
    }
    match answer_unknown_store_read(payload, &response) {
        Some(answer) => {
            crate::resident_diagnostics::note("client_state_foreign_store_read_local", 1);
            answer
        }
        None => response,
    }
}

/// This runtime's answer to a store read `response` says the resident does
/// not know, or `None` when the response stands.
fn answer_unknown_store_read(payload: &[u8], response: &[u8]) -> Option<Vec<u8>> {
    if !reports_unknown_method(response) {
        return None;
    }
    let envelope = crate::strict_json_value(payload).ok()?;
    if envelope.get("operation").and_then(Value::as_str) != Some(STORE_OPERATION) {
        return None;
    }
    let request: GuardStoreRequestV1 =
        serde_json::from_value(envelope.get("request")?.clone()).ok()?;
    if !answers_locally(&request.method) {
        return None;
    }
    crate::guard_store_op::evaluate_guard_store_request_with_owner(&request, None).ok()
}

fn answers_locally(method: &str) -> bool {
    matches!(method_kind(method), Some(Kind::Read | Kind::Snapshot))
        && !WRITES_ON_ITS_OWN.contains(&method)
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
