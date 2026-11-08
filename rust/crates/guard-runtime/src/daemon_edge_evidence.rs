//! `GET /v1/evidence`, answered as the daemon's dashboard records read
//! answers it: newest evidence first, without details, every text value
//! redacted as `store_evidence._redact_export_value` redacts it, and the
//! count of evidence the same filters match.

use guard_command::cloud_scrub::redact_sensitive_text;
use guard_command::redacted_command_tokens::redact_text;
use serde_json::{json, Map, Value};

use super::super::http::{query_int, query_value};
use super::{NativeReads, ReadConfig};
use crate::hook_cli_emit_redaction_text::redact_local_path;

const DEFAULT_LIMIT: i64 = 100;
const MAX_LIMIT: i64 = 500;
/// The fields `evidence_record_to_dict` writes when it leaves out `details`.
const FIELDS: [&str; 12] = [
    "evidence_id",
    "action_id",
    "request_id",
    "harness",
    "workspace",
    "signal_id",
    "category",
    "severity",
    "confidence",
    "summary",
    "action_identity",
    "created_at",
];

/// The daemon's answer, or `None` when it would read the request or a row
/// differently, or names no home to shorten paths against.
pub(super) fn list(query: &str, config: &ReadConfig, reads: &NativeReads) -> Option<(u16, Value)> {
    let home = config.user_home.as_deref()?;
    let harness = query_value(query, "harness").ok()?;
    let category = query_value(query, "category").ok()?;
    let severity = query_value(query, "severity").ok()?;
    let before = query_value(query, "before").ok()?;
    let limit = query_int(query, "limit", DEFAULT_LIMIT)
        .ok()?
        .clamp(1, MAX_LIMIT);
    let mut args = json!({
        "harness": harness,
        "category": category,
        "severity": severity,
        "request_id": null,
        "action_identity": null,
        "before_cursor": before,
        "include_details": false,
    });
    // `list_evidence` reads as many pages as the rows need.
    let mut items = Vec::new();
    while (items.len() as i64) < limit {
        args["limit"] = Value::from(limit - items.len() as i64);
        let page = reads.store_call(config, "list_evidence", args.clone())?;
        let rows = page.get("rows")?.as_array()?;
        for row in rows {
            items.push(item(row.as_object()?, home)?);
        }
        if !page.get("more")?.as_bool()? || rows.is_empty() {
            break;
        }
        args["after"] = page.get("after")?.clone();
    }
    let total = reads
        .store_call(
            config,
            "count_evidence",
            json!({"harness": harness, "category": category, "severity": severity}),
        )?
        .as_i64()?;
    Some((200, json!({"items": items, "total": total})))
}

/// `evidence_record_to_dict(_row_to_record(row, include_details=False))`.
fn item(row: &Map<String, Value>, home: &str) -> Option<Value> {
    let mut item = Map::new();
    for field in FIELDS {
        let value = match row.get(field) {
            Some(value) => redacted(value, home)?,
            // `_row_to_record` reads only this one with `row.get`.
            None if field == "action_identity" => Value::Null,
            None => return None,
        };
        item.insert(field.to_owned(), value);
    }
    Some(Value::Object(item))
}

/// `_redact_export_value` for a stored scalar. Rows hold no lists or maps, so
/// one is left to the daemon.
fn redacted(value: &Value, home: &str) -> Option<Value> {
    match value {
        Value::String(text) => {
            let text = redact_local_path(&redact_text(text).text, Some(home));
            Some(Value::String(redact_sensitive_text(&text)))
        }
        Value::Array(_) | Value::Object(_) => None,
        scalar => Some(scalar.clone()),
    }
}

#[cfg(test)]
#[path = "daemon_edge_evidence_tests.rs"]
mod tests;
