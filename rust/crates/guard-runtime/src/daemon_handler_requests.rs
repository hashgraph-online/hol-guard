//! Request-queue and harness-action handlers.

use crate::daemon_handler_fields::{
    optional_bool, optional_string, parse_int, query_bool, query_last, query_string, ParsedInt,
};
use crate::daemon_handler_op::Reply;
use crate::policy_bundle_py::py_strip;
use guard_contracts::DaemonFieldV1;
use serde_json::json;

const REQUESTS_LIST_LIMIT_DEFAULT: i64 = 200;
const REQUESTS_LIST_LIMIT_MAX: i64 = 200;

pub(crate) fn requests_clear(status: &DaemonFieldV1, harness: &DaemonFieldV1) -> Reply {
    let status = optional_string(status).unwrap_or_else(|| "pending".to_owned());
    if !matches!(status.as_str(), "pending" | "resolved") {
        return Reply::reject(
            400,
            json!({"error": "invalid_status", "cleared": 0, "status": status}),
        );
    }
    let fields = json!({"status": status, "harness": optional_string(harness)});
    Reply::proceed(fields.clone(), fields)
}

pub(crate) fn bulk_allow(request_ids: &DaemonFieldV1) -> Reply {
    let missing = || {
        Reply::reject(
            400,
            json!({"error": "missing_request_ids", "resolved_count": 0, "failed": []}),
        )
    };
    let DaemonFieldV1::List { len, strings } = request_ids else {
        return missing();
    };
    if *len == 0 {
        return missing();
    }
    let normalized: Vec<&str> = strings
        .iter()
        .map(|item| py_strip(item))
        .filter(|item| !item.is_empty())
        .collect();
    if normalized.is_empty() {
        return missing();
    }
    Reply::proceed(json!({}), json!({"request_ids": normalized}))
}

pub(crate) fn requests_list(query: &str) -> Reply {
    let limit = match query_last(query, "limit") {
        None => REQUESTS_LIST_LIMIT_DEFAULT,
        Some(raw) => match parse_int(&raw) {
            Some(ParsedInt::Value(value)) if value >= 1 => value.min(REQUESTS_LIST_LIMIT_MAX),
            Some(ParsedInt::Huge { negative: false }) => REQUESTS_LIST_LIMIT_MAX,
            _ => return Reply::reject(400, json!({"error": "invalid_limit"})),
        },
    };
    let status = query_string(query, "status").unwrap_or_else(|| "pending".to_owned());
    let status_filter = match status.as_str() {
        "all" => None,
        "pending" | "resolved" => Some(status),
        _ => return Reply::reject(400, json!({"error": "invalid_status"})),
    };
    Reply::proceed(
        json!({}),
        json!({
            "limit": limit,
            "status": status_filter,
            "include_totals": query_bool(query, "include_totals", true),
            "cursor": query_string(query, "cursor"),
            "harness": query_string(query, "harness"),
            "search": query_string(query, "search"),
        }),
    )
}

pub(crate) fn harness_action(action: &str, dry_run: &DaemonFieldV1) -> Reply {
    if !matches!(action, "install" | "verify" | "repair" | "uninstall") {
        return Reply::reject(404, json!({"error": "not_found"}));
    }
    if action == "verify" {
        return Reply::proceed(json!({}), json!({"dry_run": null}));
    }
    match optional_bool(dry_run, true) {
        Ok(dry_run) => Reply::proceed(json!({}), json!({"dry_run": dry_run})),
        Err(()) => Reply::reject(400, json!({"error": "invalid_dry_run"})),
    }
}

/// The `cursor` of an events query: `0` when absent or not an integer.
pub(crate) fn events_cursor(query: &str) -> Reply {
    let cursor = match query_last(query, "cursor").as_deref().and_then(parse_int) {
        Some(ParsedInt::Value(value)) => value,
        Some(ParsedInt::Huge { negative: false }) => i64::MAX,
        Some(ParsedInt::Huge { negative: true }) => i64::MIN,
        None => 0,
    };
    Reply::proceed(json!({}), json!({"cursor": cursor}))
}
