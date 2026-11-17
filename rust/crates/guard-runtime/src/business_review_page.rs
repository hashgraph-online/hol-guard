//! `business_review_page` runner-authority kind: the read-only approval-queue
//! rows the local dashboard shows for saved native business requests. Ported
//! from the retired Python `business_review_queue.py`.
//!
//! The resident discovers the saved requests; the daemon checks that no SQL
//! approval row shares an id. This projects each summary into the queue's
//! display-only row, applies the queue's harness and search filters and pages
//! the rows behind the SQL pages with a cursor bound to the filtered rows.
//!
//! Request: `{"summaries": [summary, ...], "status", "harness", "search"}`
//! plus at most one of
//!
//! - `"cursor": "native-business-v1:<digest>:<offset>", "limit": n`, a page
//!   that continues the native rows;
//! - `"room": n`, the space left on the last SQL page, which takes the first
//!   rows and a cursor for the rest.
//!
//! Answer: `{"count": rows after filtering, "items": [row, ...],
//! "next_cursor": str | null}`, or `{"error": "invalid_cursor" |
//! "expired_cursor"}` for a cursor the current rows cannot continue. Without
//! `cursor` or `room` every filtered row is returned.

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::guard_store_json::dumps_sorted;
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};
use crate::skill_identity_canon::casefold;

const CURSOR_PREFIX: &str = "native-business-v1:";
const HARNESS: &str = "native-business";
const SEARCHED: [&str; 4] = ["request_id", "artifact_name", "harness", "risk_summary"];

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let summaries = args
        .get("summaries")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?;
    let filter = |key: &str| match args.get(key) {
        None | Some(Value::Null) => Ok(Value::Null),
        Some(Value::String(text)) => Ok(json!(text)),
        Some(_) => Err(ERR_INVALID),
    };
    let (status, harness, search) = (filter("status")?, filter("harness")?, filter("search")?);
    let mut items = Vec::with_capacity(summaries.len());
    for summary in summaries {
        let item = project_request(summary)?;
        if shown(&item, harness.as_str(), search.as_str()) {
            items.push(item);
        }
    }
    let count = items.len();
    let digest = || -> Result<String, &'static str> {
        let encoded = dumps_sorted(&json!({
            "items": items,
            "status": status,
            "harness": harness,
            "search": search,
        }))
        .ok_or(ERR_INVALID)?;
        Ok(hex::encode(Sha256::digest(encoded.as_bytes())))
    };
    let count_of = |key: &str| match args.get(key) {
        None => Ok(None),
        Some(value) => value
            .as_u64()
            .and_then(|value| usize::try_from(value).ok())
            .map(Some)
            .ok_or(ERR_INVALID),
    };
    let (cursor, limit, room) = (args.get("cursor"), count_of("limit")?, count_of("room")?);
    let (start, take) = match (cursor, limit, room) {
        (None, None, None) => (0, count),
        (Some(Value::String(cursor)), Some(limit), None) => {
            let Some(offset) = cursor_offset(cursor, &digest()?, status.as_str()) else {
                return Ok(json!({ "error": "invalid_cursor" }));
            };
            if offset >= count {
                return Ok(json!({ "error": "expired_cursor" }));
            }
            (offset, limit)
        }
        (None, None, Some(room)) => (0, room),
        _ => return Err(ERR_INVALID),
    };
    let end = start.saturating_add(take).min(count);
    let next_cursor =
        (end < count).then(|| digest().map(|digest| format!("{CURSOR_PREFIX}{digest}:{end}")));
    Ok(json!({
        "count": count,
        "items": &items[start..end],
        "next_cursor": next_cursor.transpose()?,
    }))
}

/// The offset a native cursor names, when it was issued for exactly these rows.
fn cursor_offset(cursor: &str, digest: &str, status: Option<&str>) -> Option<usize> {
    let (bound, offset) = cursor.strip_prefix(CURSOR_PREFIX)?.split_once(':')?;
    let digits_only =
        !offset.is_empty() && offset.len() <= 3 && offset.bytes().all(|byte| byte.is_ascii_digit());
    if bound != digest || !digits_only || status == Some("resolved") {
        return None;
    }
    offset.parse().ok()
}

fn shown(item: &Value, harness: Option<&str>, search: Option<&str>) -> bool {
    if harness.is_some_and(|harness| !harness.is_empty() && harness != HARNESS) {
        return false;
    }
    let Some(search) = search.filter(|search| !search.is_empty()) else {
        return true;
    };
    let text = SEARCHED
        .iter()
        .map(|name| item[name].as_str().unwrap_or_default())
        .collect::<Vec<_>>()
        .join(" ");
    casefold(&text).contains(&casefold(search))
}

fn title(operation: &str) -> Option<&'static str> {
    Some(match operation {
        "mail_read" => "Read mail",
        "mail_draft" => "Save a mail draft",
        "mail_send" => "Send mail",
        "mail_label" => "Update mail labels",
        "mail_permanent_delete" => "Permanently delete mail",
        "mail_settings" => "Change mail settings",
        "drive_read" => "Read a Drive file",
        "drive_edit" => "Edit a Drive file",
        "drive_share" => "Share a Drive file",
        "drive_export" => "Export a Drive file",
        "calendar_read" => "Read a calendar",
        "calendar_invite" => "Send a calendar invitation",
        _ => return None,
    })
}

/// The display-only queue row; the explicit flag forbids UI decisions on it.
fn project_request(summary: &Value) -> Result<Value, &'static str> {
    let summary: &Map<String, Value> = summary.as_object().ok_or(ERR_INVALID)?;
    let text = |key: &str| summary.get(key).and_then(Value::as_str).ok_or(ERR_INVALID);
    let request_id = text("request_id")?;
    let title = title(text("operation")?).ok_or(ERR_INVALID)?;
    Ok(json!({
        "request_id": request_id,
        "harness": HARNESS,
        "artifact_id": request_id,
        "artifact_name": title,
        "artifact_type": "business-request",
        "artifact_hash": "",
        "publisher": null,
        "policy_action": "require-reapproval",
        "recommended_scope": null,
        "allowed_scopes": [],
        "changed_fields": [],
        "source_scope": "local",
        "config_path": "",
        "transport": "native-resident",
        "review_command": "",
        "approval_url": "",
        "status": "pending",
        "resolution_action": null,
        "resolution_scope": null,
        "reason": null,
        "created_at": "",
        "resolved_at": null,
        "native_business_review_display_only": true,
        "risk_headline": title,
        "risk_summary": "Saved native request. Review decisions and execution are not connected.",
        "queue_preview": title,
    }))
}

#[cfg(test)]
#[path = "business_review_page_tests.rs"]
mod tests;
