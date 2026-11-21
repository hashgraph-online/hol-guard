//! Command-activity list and analytics reads, validated and paged as the
//! daemon's `command_activity_api` validates and pages them.

use serde_json::{json, Map, Value};

use super::super::http::query_pairs;
use super::{NativeReads, ReadConfig};
use crate::guard_store_json::{civil_date, days_from_civil};
use cursor::{signed_cursor, verified_cursor};

const API_SCHEMA_VERSION: &str = "guard.command-activity-api.v1";
const CURSOR_PREFIX: &str = "gca1";
const PAGE_DEFAULT: i64 = 50;
const PAGE_MAX: i64 = 100;
const ANALYTICS_DAYS_MAX: i64 = 397;
const ANALYTICS_TOP_MAX: i64 = 50;
const LIST_KEYS: &[&str] = &[
    "limit",
    "cursor",
    "harness",
    "execution_status",
    "proof_level",
    "prompted",
    "approval_reuse_status",
    "extension_id",
    "rule_id",
    "occurred_from",
    "occurred_through",
];
const ANALYTICS_KEYS: &[&str] = &["days", "top_limit", "dimension", "dimension_value"];
/// `COMMAND_ACTIVITY_HARNESSES`, one per harness contract.
const HARNESSES: &[&str] = &[
    "antigravity",
    "claude-code",
    "cline",
    "codex",
    "copilot",
    "cursor",
    "devin",
    "gemini",
    "grok",
    "hermes",
    "kimi",
    "muse",
    "omp",
    "openclaw",
    "opencode",
    "paseo",
    "pi",
    "zcode",
];
const EXECUTION_STATUSES: &[&str] = &[
    "attempted",
    "prevented",
    "allowed_unconfirmed",
    "confirmed_success",
    "confirmed_failure",
    "unpaired_post",
];
const PROOF_LEVELS: &[&str] = &["pre_hook", "post_hook", "unpaired_post"];
const REUSE_STATUSES: &[&str] = &["accepted", "rejected", "not-applicable"];

/// A read the edge either answers, rejects with the daemon's 400 code, or
/// leaves to the daemon (`None`).
type Parsed<T> = Option<Result<T, &'static str>>;

macro_rules! check {
    ($parsed:expr) => {
        match $parsed? {
            Ok(value) => value,
            Err(code) => return Some(Err(code)),
        }
    };
}

/// `GET /v1/command-activity`.
pub(super) fn list(query: &str, config: &ReadConfig, reads: &NativeReads) -> Option<(u16, Value)> {
    let (filters, cursor) = match list_query(query, &config.token)? {
        Ok(parsed) => parsed,
        Err(code) => return Some(bad_request(code)),
    };
    let page = reads.store_call(
        config,
        "list_command_activity_page",
        json!({
            "filters": filters.store_filters(),
            "cursor": cursor.map(|(at, id)| json!([at, id])),
            "limit": filters.limit,
        }),
    )?;
    let items = page.get("items")?;
    if !prints_alike(items) {
        return None;
    }
    let next_cursor = match page.get("next_marker")? {
        Value::Null => Value::Null,
        // The daemon keeps the first two entries of the marker it is given.
        Value::Array(marker) => match marker.get(..2)? {
            [Value::String(at), Value::String(id)] => {
                Value::String(signed_cursor(at, id, &filters.binding(), &config.token)?)
            }
            _ => Value::Null,
        },
        _ => return None,
    };
    Some((
        200,
        json!({
            "schema_version": API_SCHEMA_VERSION,
            "items": items,
            "next_cursor": next_cursor,
        }),
    ))
}

/// `GET /v1/command-activity/analytics`. A degraded health snapshot goes to
/// the daemon, which repairs the store before it answers.
pub(super) fn analytics(
    query: &str,
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<(u16, Value)> {
    let (days, top_limit, dimension, dimension_value) = match analytics_query(query)? {
        Ok(parsed) => parsed,
        Err(code) => return Some(bad_request(code)),
    };
    let today = {
        let (year, month, day) = utc_today()?;
        days_from_civil(year, month, day)
    };
    let start = today - (days - 1);
    let payload = reads.store_call(
        config,
        "command_activity_analytics",
        json!({
            "start": iso_date(start)?,
            "end": iso_date(today)?,
            "days": days,
            "top_limit": top_limit,
            "dimension": dimension,
            "dimension_value": dimension_value,
            "feedback_from": midnight(start)?,
            "feedback_before": midnight(today + 1)?,
        }),
    )?;
    let Value::Object(payload) = payload else {
        return None;
    };
    if payload
        .get("health")
        .and_then(|health| health.get("status"))
        .is_some_and(|status| status == "degraded")
    {
        return None;
    }
    let mut body = Map::new();
    body.insert("schema_version".to_owned(), json!(API_SCHEMA_VERSION));
    body.extend(payload);
    let body = Value::Object(body);
    prints_alike(&body).then_some((200, body))
}

fn bad_request(code: &str) -> (u16, Value) {
    (400, json!({ "error": code }))
}

#[derive(Debug)]
struct ListFilters {
    limit: i64,
    harness: Option<String>,
    execution_status: Option<String>,
    proof_level: Option<String>,
    prompted: Option<bool>,
    approval_reuse_status: Option<String>,
    extension_id: Option<String>,
    rule_id: Option<String>,
    occurred_from: Option<i64>,
    occurred_through: Option<i64>,
}

impl ListFilters {
    /// `CommandActivityListQuery.binding()`.
    fn binding(&self) -> Value {
        json!([
            self.harness,
            self.execution_status,
            self.proof_level,
            self.prompted,
            self.approval_reuse_status,
            self.extension_id,
            self.rule_id,
            self.occurred_from.and_then(iso_date),
            self.occurred_through.and_then(iso_date),
        ])
    }

    fn store_filters(&self) -> Value {
        json!({
            "harness": self.harness,
            "execution_status": self.execution_status,
            "proof_level": self.proof_level,
            "approval_reuse_status": self.approval_reuse_status,
            "prompted": self.prompted,
            "extension_id": self.extension_id,
            "rule_id": self.rule_id,
            "occurred_from": self.occurred_from.and_then(midnight),
            "occurred_until": match self.occurred_through {
                Some(day) if day == days_from_civil(9999, 12, 31) => {
                    Some("9999-12-31T23:59:59.999999+00:00".to_owned())
                }
                through => through.and_then(|day| midnight(day + 1)),
            },
            "until_inclusive": self.occurred_through == Some(days_from_civil(9999, 12, 31)),
        })
    }
}

/// `parse_command_activity_list_query` and `CommandActivityListQuery`'s
/// checks, in the order the daemon raises them, then the cursor check.
fn list_query(query: &str, token: &[u8]) -> Parsed<(ListFilters, Option<(String, String)>)> {
    let mut values = check!(single_values(query, LIST_KEYS));
    let prompted = match values.remove("prompted").as_deref() {
        None => None,
        Some("true") => Some(true),
        Some("false") => Some(false),
        Some(_) => return Some(Err("invalid_prompted")),
    };
    let limit = check!(bounded_int(values.remove("limit"), PAGE_DEFAULT));
    let occurred_from = check!(optional_date(
        values.remove("occurred_from"),
        "invalid_occurred_from"
    ));
    let occurred_through = check!(optional_date(
        values.remove("occurred_through"),
        "invalid_occurred_through"
    ));
    let filters = ListFilters {
        limit,
        harness: values.remove("harness"),
        execution_status: values.remove("execution_status"),
        proof_level: values.remove("proof_level"),
        prompted,
        approval_reuse_status: values.remove("approval_reuse_status"),
        extension_id: values.remove("extension_id"),
        rule_id: values.remove("rule_id"),
        occurred_from,
        occurred_through,
    };
    if !(1..=PAGE_MAX).contains(&filters.limit) {
        return Some(Err("limit_out_of_range"));
    }
    if !one_of(&filters.harness, HARNESSES) {
        return Some(Err("invalid_harness"));
    }
    if !one_of(&filters.execution_status, EXECUTION_STATUSES) {
        return Some(Err("invalid_execution_status"));
    }
    if !one_of(&filters.proof_level, PROOF_LEVELS) {
        return Some(Err("invalid_proof_level"));
    }
    if !one_of(&filters.approval_reuse_status, REUSE_STATUSES) {
        return Some(Err("invalid_approval_reuse_status"));
    }
    if !optional_stable_id(&filters.extension_id) {
        return Some(Err("invalid_extension_id"));
    }
    if !optional_stable_id(&filters.rule_id) {
        return Some(Err("invalid_rule_id"));
    }
    if let (Some(from), Some(through)) = (occurred_from, occurred_through) {
        if from > through {
            return Some(Err("invalid_date_range"));
        }
        if through - from >= ANALYTICS_DAYS_MAX {
            return Some(Err("date_range_out_of_range"));
        }
    }
    let cursor = match values.remove("cursor") {
        None => None,
        Some(cursor) => Some(check!(verified_cursor(&cursor, &filters.binding(), token))),
    };
    Some(Ok((filters, cursor)))
}

/// `parse_command_activity_analytics_query` and its checks.
fn analytics_query(query: &str) -> Parsed<(i64, i64, Option<String>, Option<String>)> {
    let mut values = check!(single_values(query, ANALYTICS_KEYS));
    let days = check!(bounded_int(values.remove("days"), 90));
    let top_limit = check!(bounded_int(values.remove("top_limit"), 10));
    let dimension = values.remove("dimension");
    let dimension_value = values.remove("dimension_value");
    if !(1..=ANALYTICS_DAYS_MAX).contains(&days) {
        return Some(Err("days_out_of_range"));
    }
    if !(1..=ANALYTICS_TOP_MAX).contains(&top_limit) {
        return Some(Err("top_limit_out_of_range"));
    }
    if dimension.is_none() != dimension_value.is_none() {
        return Some(Err("incomplete_dimension_filter"));
    }
    if !one_of(&dimension, &["harness", "extension", "rule"]) {
        return Some(Err("invalid_dimension"));
    }
    if !optional_stable_id(&dimension_value) {
        return Some(Err("invalid_dimension_value"));
    }
    if dimension.as_deref() == Some("harness") && !one_of(&dimension_value, HARNESSES) {
        return Some(Err("invalid_harness"));
    }
    Some(Ok((days, top_limit, dimension, dimension_value)))
}

/// `_single_query_values`.
fn single_values(
    query: &str,
    allowed: &[&str],
) -> Parsed<std::collections::HashMap<String, String>> {
    if query.len() > 8_192 {
        return Some(Err("query_too_long"));
    }
    let mut values = std::collections::HashMap::new();
    for (key, value) in query_pairs(query).ok()? {
        if !allowed.contains(&key.as_str()) {
            return Some(Err("unknown_query_parameter"));
        }
        if values.contains_key(&key) || value.is_empty() {
            return Some(Err("invalid_query_parameter"));
        }
        values.insert(key, value);
    }
    Some(Ok(values))
}

/// `_bounded_int`: `int(value)` for ASCII text — surrounding whitespace, a
/// sign, and single underscores between digits — or the daemon's
/// `invalid_integer`. Other text goes to the daemon, whose `int()` also reads
/// non-ASCII digits.
fn bounded_int(value: Option<String>, default: i64) -> Parsed<i64> {
    let Some(value) = value else {
        return Some(Ok(default));
    };
    Some(crate::daemon_edge::http::python_int(&value).ok_or("invalid_integer"))
}

/// `_optional_date`: the canonical `YYYY-MM-DD` spelling of a real date, as
/// days since the epoch.
fn optional_date(value: Option<String>, code: &'static str) -> Parsed<Option<i64>> {
    let Some(value) = value else {
        return Some(Ok(None));
    };
    Some(parse_date(&value).map(Some).ok_or(code))
}

fn parse_date(value: &str) -> Option<i64> {
    let bytes = value.as_bytes();
    if bytes.len() != 10 || bytes[4] != b'-' || bytes[7] != b'-' {
        return None;
    }
    let number = |range: std::ops::Range<usize>| -> Option<i64> {
        let part = &value[range];
        part.bytes()
            .all(|byte| byte.is_ascii_digit())
            .then(|| part.parse().ok())
            .flatten()
    };
    let (year, month, day) = (number(0..4)?, number(5..7)?, number(8..10)?);
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    let month_days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return None,
    };
    (year >= 1 && (1..=month_days).contains(&day)).then(|| days_from_civil(year, month, day))
}

fn one_of(value: &Option<String>, allowed: &[&str]) -> bool {
    value
        .as_deref()
        .is_none_or(|value| allowed.contains(&value))
}

/// `_require_optional_stable_id`: `[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*`, at
/// most 256 characters.
fn optional_stable_id(value: &Option<String>) -> bool {
    let Some(value) = value.as_deref() else {
        return true;
    };
    let bytes = value.as_bytes();
    if bytes.len() > 256 || !bytes.first().is_some_and(u8::is_ascii_lowercase) {
        return false;
    }
    let mut after_separator = false;
    for &byte in &bytes[1..] {
        match byte {
            b'a'..=b'z' | b'0'..=b'9' => after_separator = false,
            b'.' | b'_' | b'-' if !after_separator => after_separator = true,
            _ => return false,
        }
    }
    !after_separator
}

/// Whether every number prints as Python's `json.dumps` prints it: integers
/// and floats Python writes without an exponent.
pub(super) fn prints_alike(value: &Value) -> bool {
    match value {
        Value::Number(number) => {
            number.is_i64()
                || number.is_u64()
                || number
                    .as_f64()
                    .is_some_and(|float| float == 0.0 || (1e-4..1e16).contains(&float.abs()))
        }
        Value::Array(items) => items.iter().all(prints_alike),
        Value::Object(map) => map.values().all(prints_alike),
        _ => true,
    }
}

fn utc_today() -> Option<(i64, i64, i64)> {
    let seconds = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_secs();
    Some(civil_date(i64::try_from(seconds / 86_400).ok()?))
}

/// `date.isoformat()`, for the years `date` holds.
fn iso_date(days: i64) -> Option<String> {
    let (year, month, day) = civil_date(days);
    (1..=9999)
        .contains(&year)
        .then(|| format!("{year:04}-{month:02}-{day:02}"))
}

/// `datetime.combine(day, time.min, tzinfo=timezone.utc).isoformat()`.
fn midnight(days: i64) -> Option<String> {
    Some(format!("{}T00:00:00+00:00", iso_date(days)?))
}

#[path = "daemon_edge_activity_cursor.rs"]
mod cursor;
#[path = "daemon_edge_activity_extensions.rs"]
pub(super) mod extensions;

#[cfg(all(test, unix))]
#[path = "daemon_edge_activity_tests.rs"]
mod tests;
