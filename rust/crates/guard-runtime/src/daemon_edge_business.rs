//! The local dashboard's saved native business requests, answered as the
//! daemon's `business_review_summary` and `business_review_queue` modules
//! answered them: `GET /v1/requests/{id}/business-summary`, and the request
//! detail a local caller gets for an id the store does not hold.
//!
//! The resident owns the frozen snapshots. These reads never stage, approve
//! or dispatch work, and never echo the resident's private failure detail.

use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::time::Duration;

use serde_json::{json, Map, Value};

use super::{NativeReads, ReadConfig};

const SUMMARY_TIMEOUT: Duration = Duration::from_secs(2);
const QUEUE_REQUEST: &[u8] = br#"{"operation":"workspace_review_local_queue","request":{}}"#;
const QUEUE_SCHEMA: &str = "guard-native-local-business-review-queue.v1";
const MAX_QUEUE_ITEMS: usize = 128;
/// The prefix of a cursor that continues the native rows.
pub(super) const CURSOR_PREFIX: &str = "native-business-v1:";
const SUMMARY_SCHEMA: &str = "guard-native-local-business-review-summary.v1";
const UNAVAILABLE: &str = "native_local_business_summary_unavailable";
const READ_FAILED: &str = "native_local_business_summary_read_failed";
const FIELDS: [&str; 18] = [
    "schema",
    "version",
    "request_id",
    "request_snapshot_digest",
    "prepared_input_binding",
    "service",
    "operation",
    "audience_kind",
    "audience_expansion_state",
    "recipient_count",
    "record_count",
    "byte_count",
    "attachment_count",
    "inspection_state",
    "sensitivity_labels",
    "snapshot_fact_completeness",
    "account_currentness",
    "execution_state",
];
const COUNTS: [&str; 4] = [
    "recipient_count",
    "record_count",
    "byte_count",
    "attachment_count",
];
const STATES: [&str; 3] = ["known", "unknown", "unsupported"];
const LABELS: [&str; 5] = ["public", "personal", "confidential", "secret", "unknown"];
const AUDIENCES: [&str; 4] = ["private", "named", "public", "unknown"];
/// The resident's answers that mean no saved request, not a failed read.
const ABSENT: [&str; 4] = [
    UNAVAILABLE,
    "native_workspace_review_request_missing",
    "native_policy_snapshot_missing",
    "native_policy_snapshot_unavailable",
];

/// A summary or queue read that could not be trusted.
#[derive(Debug)]
pub(super) struct ReadFailed;

/// A native page could not continue the caller's cursor.
#[derive(Debug, PartialEq)]
pub(super) enum PageError {
    Read,
    Cursor,
}

/// `GET /v1/requests/{id}/business-summary`: the answer, always `no-store`.
pub(super) fn summary(
    raw_id: &str,
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<(u16, Value)> {
    let request_id = crate::runner_sync_url::unquote(raw_id);
    // The store owns its detail route. Never attach another native snapshot's
    // metadata to that review, even when an opaque selector collides.
    if !store_row(&request_id, config, reads)?.is_null() {
        return Some((404, json!({"error": UNAVAILABLE})));
    }
    Some(match read_summary(config, &request_id) {
        Err(ReadFailed) => (503, json!({"error": READ_FAILED})),
        Ok(None) => (404, json!({"error": UNAVAILABLE})),
        Ok(Some(summary)) => (200, Value::Object(summary)),
    })
}

/// `GET /v1/requests/{id}` from a local caller for an id the store does not
/// hold: the saved native business request's queue row, a not-found body with
/// the queue link, or the recovery body when the snapshot cannot be checked.
/// The `bool` is whether the answer is `no-store`.
pub(super) fn unknown_detail(
    raw_id: &str,
    local: SocketAddr,
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<(u16, Value, bool)> {
    let queue_url = local_url(local, "/#/inbox");
    let request_id = crate::runner_sync_url::unquote(raw_id);
    // The store looked the raw id up; a row under the decoded id must not be
    // shadowed by a native snapshot of the same name.
    let collides = request_id != raw_id && !store_row(&request_id, config, reads)?.is_null();
    let summary = if collides {
        Err(ReadFailed)
    } else {
        read_summary(config, &request_id)
    };
    let row = summary.and_then(|summary| match summary {
        None => Ok(None),
        Some(summary) => queue_row(summary),
    });
    Some(match row {
        Ok(Some(row)) => (200, row, true),
        Ok(None) => (404, not_found(&queue_url), false),
        Err(ReadFailed) => (503, unavailable(&queue_url), true),
    })
}

/// `_local_queue_url` style links: the address the caller reached.
pub(super) fn local_url(local: SocketAddr, path: &str) -> String {
    match local.ip() {
        IpAddr::V6(address) => format!("http://[{address}]:{}{path}", local.port()),
        IpAddr::V4(address) => format!("http://{address}:{}{path}", local.port()),
    }
}

/// The daemon's body for an id that names no waiting request.
pub(super) fn not_found(queue_url: &str) -> Value {
    json!({
        "error": "not_found",
        "recovery": {
            "code": "request_unknown",
            "title": "This request is no longer waiting.",
            "body": "The request was either already resolved or expired. You can close this tab.",
            "queue_url": queue_url,
        },
    })
}

fn unavailable(queue_url: &str) -> Value {
    json!({
        "error": "native_local_business_queue_read_failed",
        "message": "Saved request details could not be verified. Refresh this request or return to the queue.",
        "recovery": {
            "code": "request_unavailable",
            "title": "Request details are unavailable.",
            "body": "The saved request could not be checked. Refresh this request or return to the queue.",
            "queue_url": queue_url,
        },
    })
}

fn store_row(request_id: &str, config: &ReadConfig, reads: &NativeReads) -> Option<Value> {
    reads.store_call(
        config,
        "get_approval_request",
        json!({"request_id": request_id}),
    )
}

/// Every saved native business request the resident verifies, each checked
/// against the store so a SQL row can never impersonate or hide one.
pub(super) fn summaries(
    config: &ReadConfig,
    reads: &NativeReads,
) -> Result<Vec<Map<String, Value>>, ReadFailed> {
    let response = resident(config, QUEUE_REQUEST)?;
    let summaries = queue_summaries(&response)?;
    for summary in &summaries {
        let request_id = summary
            .get("request_id")
            .and_then(Value::as_str)
            .ok_or(ReadFailed)?;
        if !store_row(request_id, config, reads)
            .ok_or(ReadFailed)?
            .is_null()
        {
            return Err(ReadFailed);
        }
    }
    Ok(summaries)
}

/// `read_native_business_review_queue`'s check of the resident's answer.
fn queue_summaries(response: &Value) -> Result<Vec<Map<String, Value>>, ReadFailed> {
    let object = response.as_object().ok_or(ReadFailed)?;
    let keys: Vec<&str> = object.keys().map(String::as_str).collect();
    // No installed policy is an optional feature's absence. Corrupt or stale
    // state and transport failures are never an empty queue.
    if matches!(keys.as_slice(), ["error"] | ["error", "retryable"])
        && object.get("retryable").is_none_or(Value::is_boolean)
        && matches!(
            object.get("error").and_then(Value::as_str),
            Some("native_policy_snapshot_missing" | "native_policy_snapshot_unavailable")
        )
    {
        return Ok(Vec::new());
    }
    let mut sorted = keys.clone();
    sorted.sort_unstable();
    let items = object.get("items").and_then(Value::as_array);
    let (true, Some(items)) = (
        sorted == ["items", "schema", "version"]
            && object.get("schema").and_then(Value::as_str) == Some(QUEUE_SCHEMA)
            && object.get("version").and_then(Value::as_u64) == Some(1),
        items,
    ) else {
        return Err(ReadFailed);
    };
    if items.len() > MAX_QUEUE_ITEMS {
        return Err(ReadFailed);
    }
    let mut summaries = Vec::with_capacity(items.len());
    let mut previous = "";
    for item in items {
        let request_id = item
            .get("request_id")
            .and_then(Value::as_str)
            .filter(|id| valid_request_id(id) && *id > previous)
            .ok_or(ReadFailed)?;
        summaries.push(valid_summary(item, request_id).ok_or(ReadFailed)?);
        previous = request_id;
    }
    Ok(summaries)
}

/// `_native_page`: the runtime projects, filters and pages the rows.
pub(super) fn page(
    summaries: &[Map<String, Value>],
    request: Value,
) -> Result<Map<String, Value>, PageError> {
    let Value::Object(mut request) = request else {
        return Err(PageError::Read);
    };
    if summaries.is_empty() {
        // An empty queue needs no runtime; no native cursor can name it.
        if request.contains_key("cursor") {
            return Err(PageError::Cursor);
        }
        let mut empty = Map::new();
        empty.insert("count".to_owned(), Value::from(0));
        empty.insert("items".to_owned(), Value::Array(Vec::new()));
        empty.insert("next_cursor".to_owned(), Value::Null);
        return Ok(empty);
    }
    request.insert(
        "summaries".to_owned(),
        Value::Array(summaries.iter().cloned().map(Value::Object).collect()),
    );
    let Value::Object(page) = crate::business_review_page::dispatch(&Value::Object(request))
        .map_err(|_| PageError::Read)?
    else {
        return Err(PageError::Read);
    };
    if matches!(
        page.get("error").and_then(Value::as_str),
        Some("invalid_cursor" | "expired_cursor")
    ) {
        return Err(PageError::Cursor);
    }
    let shaped = page
        .get("count")
        .is_some_and(|count| count.is_u64() || count.is_i64())
        && page.get("items").is_some_and(Value::is_array)
        && page
            .get("next_cursor")
            .is_some_and(|next| next.is_null() || next.is_string());
    shaped.then_some(page).ok_or(PageError::Read)
}

/// The one-summary page `business_review_page` projects, as the queue shows it.
fn queue_row(summary: Map<String, Value>) -> Result<Option<Value>, ReadFailed> {
    let page = crate::business_review_page::dispatch(&json!({"summaries": [summary]}))
        .map_err(|_| ReadFailed)?;
    let items = page
        .get("items")
        .and_then(Value::as_array)
        .ok_or(ReadFailed)?;
    Ok(items.first().cloned())
}

fn read_summary(
    config: &ReadConfig,
    request_id: &str,
) -> Result<Option<Map<String, Value>>, ReadFailed> {
    if !valid_request_id(request_id) {
        return Ok(None);
    }
    let payload = serde_json::to_vec(&json!({
        "operation": "workspace_review_local_summary",
        "request": {"request_id": request_id},
    }))
    .map_err(|_| ReadFailed)?;
    let response = resident(config, &payload)?;
    if absent(&response) {
        return Ok(None);
    }
    valid_summary(&response, request_id)
        .map(Some)
        .ok_or(ReadFailed)
}

/// One bounded resident read. The resident runs under the daemon's Guard home.
fn resident(config: &ReadConfig, payload: &[u8]) -> Result<Value, ReadFailed> {
    let state_dir = std::fs::canonicalize(Path::new(&config.guard_home))
        .map_err(|_| ReadFailed)?
        .join("native-runtime");
    let encoded = crate::managed_resident::client_request(&state_dir, payload, SUMMARY_TIMEOUT)
        .map_err(|_| ReadFailed)?;
    serde_json::from_slice(&encoded).map_err(|_| ReadFailed)
}

/// `[A-Za-z0-9_.:-]{1,128}`.
fn valid_request_id(request_id: &str) -> bool {
    (1..=128).contains(&request_id.len())
        && request_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-'))
}

fn absent(response: &Value) -> bool {
    let Some(response) = response.as_object() else {
        return false;
    };
    let keys: Vec<&str> = response.keys().map(String::as_str).collect();
    matches!(keys.as_slice(), ["error"] | ["error", "retryable"])
        && response.get("retryable").is_none_or(Value::is_boolean)
        && response
            .get("error")
            .and_then(Value::as_str)
            .is_some_and(|error| ABSENT.contains(&error))
}

/// The finite presentation wire shape; never a policy decision.
fn valid_summary(value: &Value, request_id: &str) -> Option<Map<String, Value>> {
    let value = value.as_object()?;
    if value.len() != FIELDS.len() || FIELDS.iter().any(|field| !value.contains_key(*field)) {
        return None;
    }
    let text = |name: &str| value.get(name).and_then(Value::as_str);
    let one_of = |name: &str, allowed: &[&str]| text(name).is_some_and(|v| allowed.contains(&v));
    let digest = |name: &str| {
        text(name).is_some_and(|v| {
            v.len() == 64
                && v.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
    };
    let operations: &[&str] = match text("service")? {
        "google_gmail" => &[
            "mail_read",
            "mail_draft",
            "mail_send",
            "mail_label",
            "mail_permanent_delete",
            "mail_settings",
        ],
        "google_drive" => &["drive_read", "drive_edit", "drive_share", "drive_export"],
        "google_calendar" => &["calendar_read", "calendar_invite"],
        _ => return None,
    };
    let count_ok = |name: &str| {
        value
            .get(name)
            .and_then(Value::as_u64)
            .is_some_and(|count| count < (1 << 53))
    };
    let labels = value.get("sensitivity_labels")?.as_array()?;
    let mut seen = Vec::with_capacity(labels.len());
    for label in labels {
        let label = label.as_str().filter(|label| LABELS.contains(label))?;
        if seen.contains(&label) {
            return None;
        }
        seen.push(label);
    }
    let shape_ok = text("schema") == Some(SUMMARY_SCHEMA)
        && value.get("version").and_then(Value::as_u64) == Some(1)
        && text("request_id") == Some(request_id)
        && text("account_currentness") == Some("not_asserted")
        && text("execution_state") == Some("not_checked")
        && digest("request_snapshot_digest")
        && digest("prepared_input_binding")
        && one_of("operation", operations)
        && one_of("audience_kind", &AUDIENCES)
        && [
            "audience_expansion_state",
            "inspection_state",
            "snapshot_fact_completeness",
        ]
        .iter()
        .all(|name| one_of(name, &STATES))
        && COUNTS.iter().all(|name| count_ok(name));
    shape_ok.then(|| value.clone())
}

#[cfg(test)]
#[path = "daemon_edge_business_tests.rs"]
mod tests;
