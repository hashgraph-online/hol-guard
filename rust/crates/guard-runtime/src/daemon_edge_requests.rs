//! `GET /v1/requests`, answered as the daemon's dashboard request list answers
//! it: the same native option check, the same store pages, and the local
//! dashboard's native business queue check.
//!
//! The edge answers the first page only. A cursor, a native business queue
//! with rows in it, or a queue that cannot be read goes to the daemon, which
//! merges native rows and writes the recovery bodies.

use std::path::Path;
use std::time::Duration;

use serde_json::{json, Map, Value};

use super::super::http::query_value;
use super::{NativeReads, ReadConfig};
use crate::daemon_handler_requests::requests_list;

const MAX_STORE_CHUNKS: usize = 10_000;
const QUEUE_TIMEOUT: Duration = Duration::from_secs(2);
const QUEUE_REQUEST: &[u8] = br#"{"operation":"workspace_review_local_queue","request":{}}"#;
const QUEUE_SCHEMA: &str = "guard-native-local-business-review-queue.v1";

/// The answer, and whether the daemon would send it with
/// `Cache-Control: no-store`.
pub(super) fn list(
    query: &str,
    hosted: bool,
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<(u16, Value, bool)> {
    let (proceed, status, body, fields) = requests_list(query).into_parts();
    if !proceed {
        return Some((status, body, false));
    }
    if !fields.get("cursor")?.is_null() {
        return None;
    }
    let mut page = store_page(&fields, config, reads)?;
    if hosted {
        return Some((200, Value::Object(page), true));
    }
    let harness = fields.get("harness")?.as_str();
    let include_totals = fields.get("include_totals")?.as_bool()?;
    let resolved = fields.get("status")?.as_str() == Some("resolved");
    // Other harnesses cannot hold native rows, and without totals neither
    // resolved history nor an unfinished SQL page reads the native queue.
    if harness.is_some_and(|harness| harness != "native-business")
        || (!include_totals && (resolved || !page.get("next_cursor")?.is_null()))
    {
        return Some((200, Value::Object(page), true));
    }
    if !native_queue_empty(config)? {
        return None;
    }
    page.insert(
        "native_business_queue_checked".to_owned(),
        Value::Bool(true),
    );
    Some((200, Value::Object(page), true))
}

/// `GET /v1/requests/{id}` for the hosted dashboard, which the daemon answers
/// with the stored row less its private queue hint.
///
/// A local caller gets read-time extension and connector recommendations, a
/// wait asks the daemon to hold the read, and an unknown id gets the local
/// queue link, so all of those go to the daemon. So does a row that may carry
/// a temporary MCP or local tool grant offer, which only the daemon attaches.
pub(super) fn detail(
    request_id: &str,
    query: &str,
    hosted: bool,
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<(u16, Value)> {
    if !hosted || request_id.contains('%') || query_value(query, "wait_ms").ok()?.is_some() {
        return None;
    }
    let cwd = config.daemon_cwd.as_deref()?;
    let Value::Object(mut approval) = reads.store_call(
        config,
        "get_approval_request",
        json!({"request_id": request_id, "derive_scope": true, "cwd": cwd}),
    )?
    else {
        return None;
    };
    if may_carry_grant_offer(&approval) {
        return None;
    }
    approval.remove("extension_allow_hint");
    Some((200, Value::Object(approval)))
}

/// `_with_approval_hints` asks the resident about a filed browser intent, or
/// about scanner evidence that names the local-tool scanner.
fn may_carry_grant_offer(approval: &Map<String, Value>) -> bool {
    approval.get("browser_intent").is_some_and(Value::is_object)
        || approval
            .get("scanner_evidence")
            .and_then(Value::as_array)
            .is_some_and(|entries| {
                entries.iter().any(|entry| {
                    entry.get("source").and_then(Value::as_str) == Some("trusted_local_tool")
                })
            })
}

/// `GET /v1/requests/{id}/resume` for a request whose resume is already
/// recorded. A request with no record yet goes to the daemon, which seeds one.
pub(super) fn resume(
    request_id: &str,
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<(u16, Value)> {
    let not_found = || Some((404, json!({"error": "not_found"})));
    let approval = reads.store_call(
        config,
        "get_approval_request",
        json!({"request_id": request_id}),
    )?;
    if approval.is_null() {
        return not_found();
    }
    let resume = reads.store_call(
        config,
        "get_request_resume",
        json!({"request_id": request_id}),
    )?;
    resume.is_object().then_some((200, resume))
}

/// `list_approval_request_page`: every chunk of the one page.
fn store_page(
    fields: &Value,
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<Map<String, Value>> {
    // The page op resolves a relative config path from the daemon's working
    // directory, which the handshake names.
    let cwd = config.daemon_cwd.clone()?;
    let mut args = json!({
        "status": fields.get("status")?,
        "limit": fields.get("limit")?,
        "cursor": null,
        "harness": fields.get("harness")?,
        "search": fields.get("search")?,
        "include_totals": fields.get("include_totals")?,
        "exclude_watch_only": false,
        "cwd": cwd,
    });
    let mut items = Vec::new();
    for _ in 0..MAX_STORE_CHUNKS {
        let Value::Object(mut chunk) =
            reads.store_call(config, "list_approval_request_page", args.clone())?
        else {
            return None;
        };
        let Value::Array(rows) = chunk.remove("items")? else {
            return None;
        };
        items.extend(rows);
        match chunk.remove("complete")? {
            Value::Bool(true) => {
                chunk.insert("items".to_owned(), Value::Array(items));
                return Some(chunk);
            }
            Value::Bool(false) => {
                args["after"] = chunk.remove("after")?;
                args["taken"] = Value::from(items.len());
            }
            _ => return None,
        }
    }
    None
}

/// The daemon's working directory, which the edge inherits; the store
/// resolves a relative config path from it.
/// Whether the resident reports no native business rows: an empty queue, or
/// no installed policy. `None` for rows, a failure, or an answer the daemon's
/// reader would not accept, all of which the daemon reads itself.
fn native_queue_empty(config: &ReadConfig) -> Option<bool> {
    // The daemon's client pins the same directory before it looks for a
    // resident; a missing one goes to the daemon.
    let state_dir =
        std::fs::canonicalize(Path::new(&config.guard_home).join("native-runtime")).ok()?;
    let encoded =
        crate::managed_resident::client_request(&state_dir, QUEUE_REQUEST, QUEUE_TIMEOUT).ok()?;
    queue_answer_empty(&serde_json::from_slice(&encoded).ok()?)
}

fn queue_answer_empty(response: &Value) -> Option<bool> {
    let response = response.as_object()?;
    let keys: Vec<&str> = response.keys().map(String::as_str).collect();
    if matches!(keys.as_slice(), ["error"] | ["error", "retryable"]) {
        let missing = matches!(
            response.get("error")?.as_str()?,
            "native_policy_snapshot_missing" | "native_policy_snapshot_unavailable"
        );
        let retryable_ok = response.get("retryable").is_none_or(Value::is_boolean);
        return (missing && retryable_ok).then_some(true);
    }
    if keys != ["items", "schema", "version"]
        || response.get("schema")?.as_str()? != QUEUE_SCHEMA
        || response.get("version")?.as_i64()? != 1
    {
        return None;
    }
    response
        .get("items")?
        .as_array()?
        .is_empty()
        .then_some(true)
}

#[cfg(test)]
#[path = "daemon_edge_requests_tests.rs"]
mod tests;
