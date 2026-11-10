//! The store-backed `GET` routes the edge answers by path, as the daemon's
//! Python handler answers them.

use serde_json::{json, Value};

use guard_contracts::DaemonRoutePayloadV1;

use super::super::http::{query_int, query_value, Request};
use super::{activity, evidence, inventory, records, settings};
use super::{authorize, composed, dispatch, health_details, network, plugin_updates, requests};
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
    if request.path == "/v1/healthz/details" && reads.is_standalone() {
        // Only the daemon's token reads the details, as `_header_token_is_valid`.
        super::authorize_token(request, &config.token)?;
        return health_details::respond(config, reads)
            .map(|body| (200, body, caller.cors_origin, false));
    }
    if request.path == "/v1/network/status" {
        return network::status().map(|(status, body)| (status, body, caller.cors_origin, true));
    }
    if composed::routed(request.path) {
        let dashboard_session =
            super::session_allows(request, &config.token, caller.cors_origin.as_deref());
        let answer = composed::respond(request, config, reads, dashboard_session);
        reads.report_activity();
        return answer.map(|(status, body, no_store)| (status, body, caller.cors_origin, no_store));
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
            if let Some(request_id) = single_segment(path, "/v1/mcp-policy/requests/", "") {
                return mcp_policy_request(request_id, config, reads);
            }
            if single_segment(path, "/v1/apps/", "/cloud").is_some() {
                return Some((
                    410,
                    json!({
                        "error": "legacy_cloud_handoff_disabled",
                        "message": "Use hol-guard connect for browser OAuth.",
                    }),
                ));
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

/// `GET /v1/mcp-policy/requests/<id>`: the request's status, digests and
/// write-plan counts, never its policy text.
fn mcp_policy_request(
    request_id: &str,
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<(u16, Value)> {
    let now = records::now_isoformat()?;
    let row = reads.store_call(
        config,
        "get_mcp_policy_request",
        json!({"request_id": request_id, "now": now}),
    )?;
    let Value::Object(row) = row else {
        return Some((404, json!({"error": "not_found"})));
    };
    Some((200, mcp_policy_request_body(&row)))
}

pub(super) fn mcp_policy_request_body(row: &serde_json::Map<String, Value>) -> Value {
    let text = |key: &str| row.get(key).cloned().unwrap_or(Value::Null);
    let object = |key: &str| {
        row.get(key)
            .and_then(Value::as_str)
            .filter(|value| !value.is_empty())
            .and_then(|value| serde_json::from_str::<Value>(value).ok())
            .and_then(|value| match value {
                Value::Object(map) => Some(map),
                _ => None,
            })
            .unwrap_or_default()
    };
    let result = object("result_json");
    let plan = object("plan_json");
    // `_safe_int`: a boolean counts as 0 or 1, a negative or other value as 0.
    let count = |key: &str| match result.get(key) {
        Some(Value::Bool(flag)) => i64::from(*flag),
        Some(Value::Number(number)) => number.as_i64().filter(|value| *value >= 0).unwrap_or(0),
        _ => 0,
    };
    let list = |key: &str| match plan.get(key) {
        Some(Value::Array(items)) => items.clone(),
        _ => Vec::new(),
    };
    let (additions, replacements, removals) =
        (list("additions"), list("replacements"), list("removals"));
    let status = row.get("status").and_then(Value::as_str).unwrap_or("");
    json!({
        "requestId": text("request_id"),
        "status": status,
        "documentId": text("policy_document_id"),
        "candidateDigest": text("policy_document_digest"),
        "expectedCurrentDigest": text("expected_current_digest"),
        "expectedPolicyGeneration": text("expected_policy_generation"),
        "mode": text("mode"),
        "createdAt": text("created_at"),
        "expiresAt": text("expires_at"),
        "resolvedAt": text("resolved_at"),
        "failureCode": text("failure_code"),
        "isTerminal": matches!(status, "applied" | "declined" | "expired" | "failed"),
        // The read marks a request past its expiry expired, so none reads as
        // pending and expired at once.
        "isExpired": false,
        "result": {"inserted": count("inserted"), "replaced": count("replaced")},
        "writePlan": {
            "additions": additions.clone(),
            "replacements": replacements.clone(),
            "removals": removals.clone(),
        },
        "semanticDiff": {
            "additionCount": additions.len(),
            "replacementCount": replacements.len(),
            "removalCount": removals.len(),
        },
        "activeEnforcementWarning": status == "pending",
    })
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

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::mcp_policy_request_body;

    #[test]
    fn a_policy_request_reads_as_the_dashboard_summary() {
        let row = json!({
            "request_id": "r1", "status": "applied", "policy_document_id": "d",
            "policy_document_digest": "g", "expected_current_digest": null,
            "expected_policy_generation": 3, "mode": "merge",
            "plan_json": "{\"additions\": [{\"id\": 1}], \"removals\": \"bad\"}",
            "created_at": "c", "expires_at": "e", "resolved_at": "r",
            "result_json": "{\"inserted\": true, \"replaced\": -2}", "failure_code": null,
        });
        let body = mcp_policy_request_body(row.as_object().unwrap());
        assert_eq!(body["isTerminal"], true);
        assert_eq!(body["activeEnforcementWarning"], false);
        assert_eq!(body["result"], json!({"inserted": 1, "replaced": 0}));
        assert_eq!(body["writePlan"]["removals"], json!([]));
        assert_eq!(body["semanticDiff"]["additionCount"], 1);
        assert_eq!(body["expectedCurrentDigest"], serde_json::Value::Null);
        assert_eq!(body["expectedPolicyGeneration"], 3);
    }
}
