//! The store-backed `GET` routes the edge answers by path, as the daemon's
//! Python handler answers them.

use serde_json::{json, Value};

use guard_contracts::DaemonRoutePayloadV1;

use super::super::http::{query_int, query_value, Request};
use super::{activity, evidence, inventory, records, settings};
use super::{authorize, dispatch, network, plugin_updates, requests};
use super::{NativeReads, ReadConfig, MAX_READ_STATE_PAGES};
use crate::daemon_route_session::origin_decision;

pub(super) fn respond(
    request: &Request<'_>,
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<(u16, Value, Option<String>, bool)> {
    if request.has_header("Content-Length") || request.has_header("Transfer-Encoding") {
        return None;
    }
    let caller = authorize(request, &config.token)?;
    // Reported at the start as well as the end, so a slow store read never
    // looks idle to the daemon.
    reads.report_activity();
    let hosted = caller.cors_origin.as_deref().is_some_and(|origin| {
        matches!(
            origin_decision(origin, "/"),
            DaemonRoutePayloadV1::Origin {
                hosted_origin: true,
                ..
            }
        )
    });
    if request.path == "/v1/requests" {
        return requests::list(request.query, hosted, config, reads)
            .map(|(status, body, no_store)| (status, body, caller.cors_origin, no_store));
    }
    if let Some(request_id) = single_segment(request.path, "/v1/requests/", "/resume") {
        return requests::resume(request_id, config, reads)
            .map(|(status, body)| (status, body, caller.cors_origin, false));
    }
    if let Some(request_id) = single_segment(request.path, "/v1/requests/", "") {
        return requests::detail(request_id, request.query, hosted, config, reads)
            .map(|(status, body)| (status, body, caller.cors_origin, false));
    }
    if request.path == "/v1/runtime/containment-health" {
        return network::containment_health(config)
            .map(|(status, body)| (status, body, caller.cors_origin, true));
    }
    if request.path == "/v1/plugins/updates" {
        return plugin_updates::read(config)
            .map(|(status, body)| (status, body, caller.cors_origin, true));
    }
    if request.path == "/v1/network/status" {
        return network::status().map(|(status, body)| (status, body, caller.cors_origin, true));
    }
    if let Some((status, body)) = route(request.path, request.query, config, reads) {
        return Some((status, body, caller.cors_origin, false));
    }
    if !dispatch::get_routed(request.path) {
        return None;
    }
    let answer = dispatch::answer(
        "GET",
        request.path,
        request.query,
        &serde_json::Map::new(),
        dispatch::call_library(config),
    );
    reads.report_activity();
    answer.map(|(status, body, no_store)| (status, body, caller.cors_origin, no_store))
}

/// The answer the daemon's Python route gives for the same path and query, or
/// `None` for a path it does not serve here or a query it does not read the
/// same way.
pub(super) fn route(
    path: &str,
    query: &str,
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<(u16, Value)> {
    let not_found = || (404, json!({"error": "not_found"}));
    match path {
        "/v1/receipts" => {
            let limit = query_int(query, "limit", 200).ok()?.clamp(1, 500);
            let harness = query_value(query, "harness").ok()?;
            let items = reads.store_call(
                config,
                "list_receipts",
                json!({"limit": limit, "harness": harness}),
            )?;
            items.is_array().then(|| (200, json!({"items": items})))
        }
        "/v1/receipts/latest" => {
            let harness = query_value(query, "harness").ok()?;
            let artifact_id = query_value(query, "artifact_id").ok()?;
            let (Some(harness), Some(artifact_id)) = (harness, artifact_id) else {
                return Some((400, json!({"error": "missing_receipt_query"})));
            };
            let receipt = reads.store_call(
                config,
                "get_latest_receipt",
                json!({
                    "harness": harness,
                    "artifact_id": artifact_id,
                }),
            )?;
            Some(if receipt.is_null() {
                not_found()
            } else {
                (200, receipt)
            })
        }
        "/v1/inventory" => inventory::list(config, reads),
        "/v1/supply-chain/bundle" => {
            let bundle = reads.store_call(config, "cached_supply_chain_bundle", json!({}))?;
            Some((200, json!({ "bundle": bundle })))
        }
        "/v1/policy/cloud-exceptions" => {
            let harness = query_value(query, "harness").ok()?;
            let items =
                reads.store_call(config, "list_cloud_exceptions", json!({"harness": harness}))?;
            items.is_array().then(|| (200, json!({"items": items})))
        }
        "/v1/events" => {
            let (_, _, _, fields) =
                crate::daemon_handler_requests::events_cursor(query).into_parts();
            let cursor = fields.get("cursor").and_then(Value::as_i64)?;
            let items = reads.store_call(
                config,
                "list_events_after",
                json!({"event_id": cursor, "limit": 200}),
            )?;
            items.is_array().then(|| (200, json!({"items": items})))
        }
        "/v1/read-state" => read_state(config, reads).map(|ids| (200, json!({"ids": ids}))),
        "/v1/evidence" => evidence::list(query, config, reads),
        "/v1/sessions" => records::sessions(config, reads),
        "/v1/command-activity" => activity::list(query, config, reads),
        "/v1/command-activity/analytics" => activity::analytics(query, config, reads),
        "/v1/command-activity/diagnostics" => activity::extensions::diagnostics(config, reads),
        "/v1/command-extensions" => activity::extensions::page(query, config),
        "/v1/connect/state" => Some((
            410,
            json!({
                "error": "legacy_pairing_disabled",
                "message": "Use hol-guard connect for browser OAuth.",
            }),
        )),
        "/v1/receipts/analytics" => records::receipt_analytics(query, config, reads),
        "/v1/settings" => settings::settings(config),
        "/v1/settings/export" => settings::export(config),
        _ => {
            if let Some(session_id) = single_segment(path, "/v1/sessions/", "/resume") {
                return records::session_resume(session_id, config, reads);
            }
            if let Some(operation_id) = single_segment(path, "/v1/operations/", "") {
                return records::operation(operation_id, config, reads);
            }
            // The daemon serves `/v1/receipts/analytics` itself, ahead of its
            // receipt lookup.
            if let Some(receipt_id) =
                single_segment(path, "/v1/receipts/", "").filter(|segment| *segment != "analytics")
            {
                let receipt =
                    reads.store_call(config, "get_receipt", json!({"receipt_id": receipt_id}))?;
                return Some(if receipt.is_null() {
                    not_found()
                } else {
                    (200, receipt)
                });
            }
            let artifact_id = single_segment(path, "/v1/artifacts/", "/diff")?;
            let Some(harness) = query_value(query, "harness").ok()? else {
                return Some((400, json!({"error": "missing_harness"})));
            };
            let diff = reads.store_call(
                config,
                "artifact_latest_diff",
                json!({
                    "harness": harness,
                    "artifact_id": crate::claude_hook_bridge_url::py_unquote(artifact_id),
                }),
            )?;
            Some(if diff.is_object() {
                (200, diff)
            } else {
                not_found()
            })
        }
    }
}

/// The one path segment between `prefix` and `suffix`.
pub(super) fn single_segment<'a>(path: &'a str, prefix: &str, suffix: &str) -> Option<&'a str> {
    let segment = path.strip_prefix(prefix)?.strip_suffix(suffix)?;
    (!segment.is_empty() && !segment.contains('/')).then_some(segment)
}

/// Read request ids, most recently read first, as `get_read_state` pages and
/// orders them.
pub(super) fn read_state(config: &ReadConfig, reads: &NativeReads) -> Option<Vec<Value>> {
    let mut marks: Vec<(String, String)> = Vec::new();
    let mut after = Value::Null;
    for _ in 0..MAX_READ_STATE_PAGES {
        let page = reads.store_call(config, "get_read_state", json!({"after": after}))?;
        for mark in page.get("marks")?.as_array()? {
            let [request_id, read_at] = mark.as_array()?.as_slice() else {
                return None;
            };
            marks.push((
                request_id.as_str()?.to_owned(),
                read_at.as_str()?.to_owned(),
            ));
        }
        after = page.get("after")?.clone();
        if after.is_null() {
            marks.sort_by(|left, right| right.1.cmp(&left.1));
            return Some(marks.into_iter().map(|(id, _)| Value::from(id)).collect());
        }
    }
    None
}
