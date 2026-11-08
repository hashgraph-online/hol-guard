//! Session, operation and receipt-analytics reads, answered as the daemon's
//! dashboard runtime and records reads answer them from the same native store
//! rows.

use serde_json::{json, Map, Value};

use super::super::http::query_int;
use super::{NativeReads, ReadConfig};
use crate::policy_bundle_time::micros_to_utc_isoformat;

/// `GET /v1/sessions`: `list_guard_sessions(limit=200)`.
pub(super) fn sessions(config: &ReadConfig, reads: &NativeReads) -> Option<(u16, Value)> {
    let rows = reads.store_call(
        config,
        "list_guard_sessions",
        json!({"status": null, "limit": 200}),
    )?;
    let items = rows
        .as_array()?
        .iter()
        .map(|row| session(row.as_object()?))
        .collect::<Option<Vec<_>>>()?;
    Some((200, json!({ "items": items })))
}

/// `GET /v1/operations/<id>`: `get_guard_operation`, or the daemon's 404.
pub(super) fn operation(
    operation_id: &str,
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<(u16, Value)> {
    let row = reads.store_call(
        config,
        "get_guard_operation",
        json!({"operation_id": operation_id}),
    )?;
    if row.is_null() {
        return Some((404, json!({"error": "not_found"})));
    }
    Some((200, operation_row(row.as_object()?)?))
}

/// `GET /v1/receipts/analytics`, with the daemon's bounds on each window.
pub(super) fn receipt_analytics(
    query: &str,
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<(u16, Value)> {
    let activity_days = query_int(query, "activity_days", 90).ok()?.clamp(1, 366);
    let trend_days = query_int(query, "trend_days", 7)
        .ok()?
        .clamp(1, activity_days);
    let top_limit = query_int(query, "top_limit", 10).ok()?.clamp(1, 50);
    let analytics = reads.store_call(
        config,
        "receipt_analytics",
        json!({
            "activity_days": activity_days,
            "trend_days": trend_days,
            "top_limit": top_limit,
            "now": now_isoformat()?,
        }),
    )?;
    analytics.is_object().then_some((200, analytics))
}

/// `_guard_session_row`.
fn session(row: &Map<String, Value>) -> Option<Value> {
    let mut item = Map::new();
    for field in ["session_id", "harness", "surface", "status", "client_name"] {
        item.insert(field.to_owned(), text(row, field)?);
    }
    for field in ["client_title", "client_version", "workspace"] {
        item.insert(field.to_owned(), optional_text(row, field)?);
    }
    item.insert(
        "capabilities".to_owned(),
        decoded(row, "capabilities_json")?,
    );
    for field in ["created_at", "updated_at"] {
        item.insert(field.to_owned(), text(row, field)?);
    }
    Some(Value::Object(item))
}

/// `_guard_operation_row`.
fn operation_row(row: &Map<String, Value>) -> Option<Value> {
    let mut item = Map::new();
    for field in [
        "operation_id",
        "session_id",
        "harness",
        "operation_type",
        "status",
        "created_at",
        "updated_at",
    ] {
        item.insert(field.to_owned(), text(row, field)?);
    }
    item.insert(
        "approval_request_ids".to_owned(),
        decoded(row, "approval_request_ids_json")?,
    );
    item.insert(
        "resume_token".to_owned(),
        optional_text(row, "resume_token")?,
    );
    item.insert("metadata".to_owned(), decoded(row, "metadata_json")?);
    Some(Value::Object(item))
}

/// `str(row[field])` for a text column. Any other stored type goes to the
/// daemon, whose `str()` the edge does not reproduce.
fn text(row: &Map<String, Value>, field: &str) -> Option<Value> {
    row.get(field)?.is_string().then(|| row[field].clone())
}

/// `str(row[field]) if row[field] is not None else None`.
fn optional_text(row: &Map<String, Value>, field: &str) -> Option<Value> {
    match row.get(field)? {
        Value::Null => Some(Value::Null),
        Value::String(_) => Some(row[field].clone()),
        _ => None,
    }
}

/// `json.loads(str(row[field]))`, for text both parsers read alike. A
/// fractional or out-of-range number goes to the daemon: Python prints floats
/// and big integers its own way.
fn decoded(row: &Map<String, Value>, field: &str) -> Option<Value> {
    let value: Value = serde_json::from_str(row.get(field)?.as_str()?).ok()?;
    integral(&value).then_some(value)
}

fn integral(value: &Value) -> bool {
    match value {
        Value::Number(number) => number.is_i64() || number.is_u64(),
        Value::Array(items) => items.iter().all(integral),
        Value::Object(map) => map.values().all(integral),
        _ => true,
    }
}

/// `datetime.now(timezone.utc).isoformat(timespec="microseconds")`.
fn now_isoformat() -> Option<String> {
    let micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_micros();
    let text = micros_to_utc_isoformat(i64::try_from(micros).ok()?, "+00:00")?;
    // The shared formatter leaves out a zero fraction; Python never does.
    Some(if text.contains('.') {
        text
    } else {
        text.replacen("+00:00", ".000000+00:00", 1)
    })
}

#[cfg(test)]
#[path = "daemon_edge_records_tests.rs"]
mod tests;
