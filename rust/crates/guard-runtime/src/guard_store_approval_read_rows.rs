//! `store_approval_projection._row_to_draft`: one stored approval row as the
//! queue payload, before its scope contract is attached.

use guard_command::browser_mcp_intent::classify_operation;
use serde_json::{Map, Value};

use crate::cloud_request_text::{py_isspace, py_strip};
use crate::guard_store_approval_read_scope::{parse_cell, to_json, unavailable};
use crate::guard_store_db::{Row, StoreError, StoreResult};
use crate::guard_store_json::py_repr_str;
use crate::guard_store_silent_review::{py_str, raw};
use crate::pyjson::PyVal;

const MULTI_ELEMENT_OPERATIONS: [&str; 3] = ["drag", "drag_drop_file", "fill_form"];
const ELEMENT_OPERATIONS: [&str; 7] = [
    "click",
    "fill",
    "fill_input",
    "focus_element",
    "hover",
    "select_dropdown",
    "upload_file",
];
/// Columns copied as stored, in payload order after `workspace`.
const RAW_TAIL: [&str; 7] = [
    "normalized_identity_key",
    "action_identity",
    "queue_group_id",
    "last_seen_at",
    "transport",
    "risk_summary",
    "artifact_label",
];

/// The draft payload and the projection's contract error.
pub(crate) fn draft(
    row: &Row,
    projection: &Value,
) -> StoreResult<(Map<String, Value>, Option<String>)> {
    let (launch_target, browser_target) = browser_launch_target(raw(row, "launch_target"));
    let risk_signals = risk_signals(
        json_list(row, "risk_signals_json")?,
        browser_target.as_deref(),
    );
    let mut payload = Map::new();
    let mut put = |key: &str, value: Value| {
        payload.insert(key.to_owned(), value);
    };
    let text = |name: &str| py_str(row.get(name)).map(Value::String);
    for name in [
        "request_id",
        "harness",
        "artifact_id",
        "artifact_name",
        "artifact_type",
        "artifact_hash",
    ] {
        put(name, text(name)?);
    }
    put("publisher", raw(row, "publisher"));
    put("policy_action", projection["policy_action"].clone());
    put("recommended_scope", text("recommended_scope")?);
    put(
        "changed_fields",
        Value::Array(json_list(row, "changed_fields_json")?),
    );
    put("source_scope", text("source_scope")?);
    put("oauth_source", raw(row, "oauth_source"));
    put("config_path", text("config_path")?);
    put("workspace", raw(row, "workspace"));
    put("launch_target", launch_target);
    put("dedupe_count", py_int(&raw(row, "dedupe_count"))?);
    put("display_status", text("status")?);
    put("resolution_intent", raw(row, "resolution_action"));
    put("risk_signals", Value::Array(risk_signals));
    for &name in RAW_TAIL.iter().chain(&[
        "source_label",
        "trigger_summary",
        "why_now",
        "launch_summary",
        "risk_headline",
        "fallback_cli_command",
        "raw_command_text",
        "guard_version",
        "first_seen_guard_version",
        "last_seen_guard_version",
        "resolution_action",
        "resolution_scope",
        "reason",
        "resolved_at",
    ]) {
        put(name, raw(row, name));
    }
    put(
        "action_envelope_json",
        projection["action_envelope_json"].clone(),
    );
    put("decision_v2_json", projection["decision_v2_json"].clone());
    put(
        "watch_only_observation",
        Value::Bool(py_bool(&raw(row, "watch_only_observation"))),
    );
    put(
        "scanner_evidence",
        Value::Array(json_object_list(row, "scanner_evidence_json")?),
    );
    put("browser_intent", json_object(row, "browser_intent_json")?);
    put(
        "continuation_snapshot",
        json_object(row, "continuation_snapshot_json")?,
    );
    for name in ["review_command", "approval_url", "status", "created_at"] {
        put(name, text(name)?);
    }
    let contract_error = projection["contract_error"].as_str().map(str::to_owned);
    Ok((payload, contract_error))
}

/// A decoded cell the reply carries; a lone surrogate cannot cross it.
fn decoded(value: &PyVal, surrogate: bool) -> StoreResult<Value> {
    if surrogate {
        return Err(unavailable());
    }
    to_json(value)
}

/// `_safe_json_list`.
pub(crate) fn json_list(row: &Row, name: &str) -> StoreResult<Vec<Value>> {
    match parse_cell(row, name)? {
        Some((value @ PyVal::List(_), surrogate)) => match decoded(&value, surrogate)? {
            Value::Array(items) => Ok(items),
            _ => Err(unavailable()),
        },
        _ => Ok(Vec::new()),
    }
}

/// `_json_object`.
pub(crate) fn json_object(row: &Row, name: &str) -> StoreResult<Value> {
    match parse_cell(row, name)? {
        Some((value @ PyVal::Dict(_), surrogate)) => decoded(&value, surrogate),
        _ => Ok(Value::Null),
    }
}

/// `_json_object_list`.
fn json_object_list(row: &Row, name: &str) -> StoreResult<Vec<Value>> {
    let Some((PyVal::List(items), surrogate)) = parse_cell(row, name)? else {
        return Ok(Vec::new());
    };
    items
        .iter()
        .filter(|item| matches!(item, PyVal::Dict(_)))
        .map(|item| decoded(item, surrogate))
        .collect()
}

/// `bool(cell)`.
pub(crate) fn py_bool(cell: &Value) -> bool {
    match cell {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|value| value != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(fields) => !fields.is_empty(),
    }
}

/// `int(cell or 1)`.
pub(crate) fn py_int(cell: &Value) -> StoreResult<Value> {
    let digits = match cell {
        Value::Null => "1".to_owned(),
        Value::Number(number) => match number.as_i64() {
            Some(0) => "1".to_owned(),
            Some(integer) => integer.to_string(),
            None => match number.as_f64() {
                Some(0.0) => "1".to_owned(),
                Some(float) if float.is_finite() => format!("{:.0}", float.trunc()),
                _ => number.to_string(),
            },
        },
        Value::String(text) if text.is_empty() => "1".to_owned(),
        Value::String(text) => int_literal(text).ok_or_else(|| {
            StoreError::Value(format!(
                "invalid literal for int() with base 10: {}",
                py_repr_str(text)
            ))
        })?,
        _ => return Err(StoreError::Invalid("native_guard_store_cell_invalid")),
    };
    let digits = if digits == "-0" {
        "0".to_owned()
    } else {
        digits
    };
    serde_json::from_str(&digits).map_err(|_| unavailable())
}

/// `int(text)` for ASCII decimal text: canonical digits, or `None` where
/// Python raises.
fn int_literal(text: &str) -> Option<String> {
    let body = py_strip(text);
    let (sign, body) = match body.as_bytes().first() {
        Some(b'-') => ("-", &body[1..]),
        Some(b'+') => ("", &body[1..]),
        _ => ("", body),
    };
    let bytes = body.as_bytes();
    let valid = !bytes.is_empty()
        && bytes.first().is_some_and(u8::is_ascii_digit)
        && bytes.last().is_some_and(u8::is_ascii_digit)
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_digit() || *byte == b'_')
        && !body.contains("__");
    if !valid {
        return None;
    }
    let digits: String = body.chars().filter(char::is_ascii_digit).collect();
    let trimmed = digits.trim_start_matches('0');
    Some(if trimmed.is_empty() {
        "0".to_owned()
    } else {
        format!("{sign}{trimmed}")
    })
}

/// `_browser_launch_target_for_display`: a legacy `server op unknown` label
/// with the target its operation names.
pub(crate) fn browser_launch_target(value: Value) -> (Value, Option<String>) {
    let Value::String(text) = &value else {
        return (value, None);
    };
    let parts: Vec<&str> = text
        .split(py_isspace)
        .filter(|part| !part.is_empty())
        .collect();
    let [server, operation, "unknown"] = parts[..] else {
        return (value, None);
    };
    if classify_operation(operation, server).is_none() {
        return (value, None);
    }
    let lower = operation.to_lowercase();
    let element = lower.strip_prefix("browser_").unwrap_or(&lower);
    let reads = lower.starts_with("get_") || lower.starts_with("read_");
    let target = if lower.contains("network") {
        if reads {
            "network request"
        } else {
            "network activity"
        }
    } else if lower.contains("console") {
        if reads {
            "console message"
        } else {
            "console messages"
        }
    } else if MULTI_ELEMENT_OPERATIONS.contains(&element) {
        "page elements"
    } else if ELEMENT_OPERATIONS.contains(&element) {
        "page element"
    } else if matches!(lower.as_str(), "list_pages" | "browser_list_pages") {
        "open pages"
    } else if matches!(
        lower.as_str(),
        "select_page" | "close_page" | "browser_select_page" | "browser_close_page"
    ) {
        "browser page"
    } else {
        "current page"
    };
    (
        Value::String(format!("{server} {operation} {target}")),
        Some(target.to_owned()),
    )
}

/// `_browser_risk_signals_for_display`.
fn risk_signals(signals: Vec<Value>, target: Option<&str>) -> Vec<Value> {
    let Some(target) = target else {
        return signals;
    };
    signals
        .into_iter()
        .map(|signal| match signal {
            Value::String(text) => Value::String(text.replace("unknown target", target)),
            other => other,
        })
        .collect()
}
