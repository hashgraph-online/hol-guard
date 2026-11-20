//! `inspect_codex_resume_capabilities`: what the same-chat Codex continuation
//! needs, and how the last attempt went.

use guard_contracts::CodexRequestResumeRequestV1;
use rusqlite::Connection;
use serde_json::{Map, Value};

use crate::codex_request_resume_op::Outcome;
use crate::codex_request_resume_store as store;
use crate::codex_thread_continue_op::{default_socket_available, ContinueRequest};
use crate::guard_store_args::Args;
use crate::guard_store_db::StoreResult;

/// The caller's default control socket is reachable, and the latest recorded
/// Codex attempt (`Null` when there is none).
pub(crate) fn capabilities(
    connection: &Connection,
    request: &CodexRequestResumeRequestV1,
) -> StoreResult<Outcome> {
    let probe = ContinueRequest {
        approval_request_id: &request.approval_request_id,
        action: "",
        home_dir: request.home_dir.as_deref(),
        temp_dir: request.temp_dir.as_deref(),
        cwd: request.cwd.as_deref(),
        timeout_ms: 0,
    };
    let filter = Map::from_iter([("harness".to_owned(), Value::from("codex"))]);
    Ok(Outcome::Capabilities {
        socket_available: default_socket_available(&probe, request.codex_home.as_deref()),
        latest_attempt: store::latest(connection, &Args(&filter))?,
    })
}

#[cfg(test)]
#[path = "codex_request_resume_capabilities_tests.rs"]
mod tests;
