//! `POST` and `DELETE` routes the daemon edge answers without the Python
//! daemon.
//!
//! The edge takes a write only when the daemon's preamble would pass it with
//! nothing left to decide: the auth token in its one `X-Guard-Token` header,
//! an allowed origin, one plain `Content-Length` and a JSON body the edge reads
//! exactly as `json.loads` would. The daemon reads any other body itself, so a
//! form body, a dashboard session, a chunked body or JSON that only Python
//! accepts goes to it untouched, with every rejection it writes today.

use guard_contracts::DaemonFieldV1;
use serde_json::{json, Map, Value};

use super::super::auth::authorize_token;
use super::super::http::Request;
use super::{read_state, NativeReads, ReadConfig};
use crate::guard_store_json::py_strip;
use crate::policy_bundle_time::micros_to_utc_isoformat;
use crate::pyjson::{self, PyVal};

const COMMAND_ACTIVITY_SCHEMA_VERSION: &str = "guard.command-activity-api.v1";
/// The status of an answer the edge never sends: the connection closes
/// unanswered, as it does when the daemon's handler raises.
pub(super) const DROPPED: u16 = 0;
/// `plugin_updates_http._SLUG_BYTES`.
const PLUGIN_SLUG_BYTES: usize = 256;
/// `native_daemon_handler._MAX_LIST_ITEMS`.
const MAX_HANDLER_LIST_ITEMS: usize = 4_096;

#[path = "daemon_edge_gate.rs"]
mod gate;
#[path = "daemon_edge_sessions.rs"]
mod sessions;
#[path = "daemon_edge_settings_write.rs"]
mod settings_write;

pub(super) fn respond(
    request: &Request<'_>,
    body: &[u8],
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<(u16, Value, Option<String>, bool)> {
    if let Some(route) = sessions::Route::parse(request.method, request.path) {
        // A dashboard session may come back refreshed from `initialize`,
        // which only the daemon signs.
        if request.has_header("Transfer-Encoding")
            || (matches!(route, sessions::Route::Initialize)
                && (request.has_header("X-Guard-Dashboard-Session")
                    || request.has_header("Authorization")))
        {
            return None;
        }
        let caller = authorize_token(request, &config.token)?;
        let payload = py_payload(request, body)?;
        reads.report_activity();
        return sessions::respond(&route, &payload, config, reads)
            .map(|(status, body)| (status, body, caller.cors_origin, false));
    }
    if request.method == "POST"
        && matches!(
            request.path,
            "/v1/settings" | "/v1/settings/import" | "/v1/settings/reset"
        )
    {
        if request.has_header("Transfer-Encoding") {
            return None;
        }
        let caller = authorize_token(request, &config.token)?;
        let payload = json_payload(request, body)?;
        let answer = if request.path == "/v1/settings/reset" {
            reads.report_activity();
            settings_write::reset(&payload, config, reads)
        } else {
            let entries = py_payload(request, body)?;
            reads.report_activity();
            let missing_error = if request.path == "/v1/settings/import" {
                "invalid_settings_import"
            } else {
                "invalid_settings"
            };
            settings_write::apply(&entries, &payload, missing_error, config, reads)
        };
        return answer.map(|(status, body)| (status, body, caller.cors_origin, false));
    }
    let route = (request.method, request.path);
    if request.has_header("Transfer-Encoding")
        || !matches!(
            route,
            (
                "POST",
                "/v1/read-state"
                    | "/v1/command-activity/feedback"
                    | "/v1/requests/clear"
                    | "/v1/plugins/updates/dismiss"
            ) | ("DELETE", "/v1/read-state" | "/v1/evidence")
        )
    {
        return None;
    }
    let caller = authorize_token(request, &config.token)?;
    if route.1 == "/v1/plugins/updates/dismiss" {
        let payload = json_payload(request, body)?;
        reads.report_activity();
        let (status, body) = plugin_update_dismiss(&payload, config);
        return Some((status, body, caller.cors_origin, true));
    }
    let answer = match route {
        ("POST", "/v1/read-state") => {
            let payload = json_payload(request, body)?;
            reads.report_activity();
            update_read_state(&payload, config, reads)
        }
        ("POST", "/v1/requests/clear") => {
            let payload = json_payload(request, body)?;
            reads.report_activity();
            requests_clear(&payload, config, reads)
        }
        ("POST", _) => {
            let payload = json_payload(request, body)?;
            reads.report_activity();
            command_activity_feedback(&payload, config, reads)
        }
        (_, "/v1/read-state") => {
            let payload = delete_payload(body)?;
            reads.report_activity();
            clear_read_state(payload.as_ref(), config, reads)
        }
        _ => {
            reads.report_activity();
            let deleted = reads.store_call(config, "clear_evidence", json!({}))?;
            Some((200, json!({"deleted": deleted.as_i64()?})))
        }
    };
    answer.map(|(status, body)| (status, body, caller.cors_origin, false))
}

/// `_handle_requests_clear`: the native option check, the approval gate, then
/// `clear_approval_requests`.
fn requests_clear(
    payload: &Map<String, Value>,
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<(u16, Value)> {
    let (proceed, status, body, fields) = crate::daemon_handler_requests::requests_clear(
        &handler_field(payload.get("status")),
        &handler_field(payload.get("harness")),
    )
    .into_parts();
    if !proceed {
        return Some((status, body));
    }
    let queue_status = fields.get("status")?.clone();
    match gate::require_high_risk("queue_clear", payload, config)? {
        gate::Gate::Refused(status, mut refusal) => {
            refusal.insert("cleared".to_owned(), Value::from(0));
            refusal.insert("status".to_owned(), queue_status);
            Some((status, Value::Object(refusal)))
        }
        gate::Gate::Passed(_) => {
            // The gate has run, so a failed write closes the connection
            // rather than have the daemon check the gate again.
            let cleared = reads.store_call(
                config,
                "clear_approval_requests",
                json!({"harness": fields.get("harness")?, "status": queue_status}),
            );
            let Some(cleared) = cleared.as_ref().and_then(Value::as_i64) else {
                return Some((DROPPED, Value::Null));
            };
            let mut answer = Map::new();
            answer.insert("cleared".to_owned(), Value::from(cleared));
            answer.extend(body.as_object()?.clone());
            Some((200, Value::Object(answer)))
        }
    }
}

/// `handle_plugin_updates_dismiss`: the daemon's slug and version checks,
/// then the plugin telemetry dismissal it runs.
fn plugin_update_dismiss(payload: &Map<String, Value>, config: &ReadConfig) -> (u16, Value) {
    let text = |key| {
        payload
            .get(key)
            .and_then(Value::as_str)
            .map(py_strip)
            .filter(|value| !value.is_empty())
    };
    let slug = text("slug").filter(|slug| slug.len() <= PLUGIN_SLUG_BYTES);
    let version = text("version").filter(|version| plugin_version_valid(version));
    let (Some(slug), Some(version)) = (slug, version) else {
        return (
            400,
            json!({
                "error": "invalid_plugin_update",
                "message": "Name the listing slug and the version to dismiss.",
            }),
        );
    };
    let request = json!({
        "command": "updates-dismiss",
        "guardHome": config.guard_home,
        "slug": slug,
        "version": version,
    });
    let mut response = guard_plugin_telemetry::run_request(request.to_string().as_bytes());
    if response.get("ok") == Some(&Value::Bool(true)) {
        if let Some(result @ Value::Object(_)) = response.get_mut("result").map(Value::take) {
            return (200, result);
        }
    }
    let code = match response.get("error") {
        Some(Value::String(code)) if !code.is_empty() => code.clone(),
        _ => "no result".to_owned(),
    };
    (
        503,
        json!({
            "error": "plugin_updates_unavailable",
            "message": format!("The Guard native runtime refused the report ({code})."),
        }),
    )
}

/// `plugin_updates_http._VERSION`: `[A-Za-z0-9][A-Za-z0-9.+_-]{0,63}`.
fn plugin_version_valid(version: &str) -> bool {
    let bytes = version.as_bytes();
    (1..=64).contains(&bytes.len())
        && bytes[0].is_ascii_alphanumeric()
        && bytes
            .iter()
            .all(|byte| byte.is_ascii_alphanumeric() || b".+_-".contains(byte))
}

/// `native_daemon_handler._field`: how the daemon hands one body value to
/// the native option check.
fn handler_field(value: Option<&Value>) -> DaemonFieldV1 {
    match value {
        None | Some(Value::Null) => DaemonFieldV1::Absent,
        Some(Value::Bool(value)) => DaemonFieldV1::Bool { value: *value },
        Some(Value::String(value)) => DaemonFieldV1::Text {
            value: value.clone(),
        },
        Some(Value::Array(items)) => DaemonFieldV1::List {
            len: items.len(),
            strings: if items.len() <= MAX_HANDLER_LIST_ITEMS {
                items
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_owned))
                    .collect()
            } else {
                Vec::new()
            },
        },
        Some(_) => DaemonFieldV1::Other,
    }
}

/// `handle_command_activity_feedback`: the daemon's payload checks, then
/// `record_command_activity_feedback`.
fn command_activity_feedback(
    payload: &Map<String, Value>,
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<(u16, Value)> {
    let invalid = |error: &str| Some((400, json!({ "error": error })));
    if payload.len() != 2 || !payload.contains_key("activity_id") || !payload.contains_key("label")
    {
        return invalid("invalid_feedback_payload");
    }
    let activity_id = match payload.get("activity_id") {
        Some(Value::String(id)) if !id.is_empty() && id.chars().count() <= 256 => id,
        _ => return invalid("invalid_activity_id"),
    };
    let label = match payload.get("label").and_then(Value::as_str) {
        Some(label @ ("should_not_have_interrupted" | "expected_guard_to_stop_this")) => label,
        _ => return invalid("invalid_feedback_label"),
    };
    let Value::Object(mut answer) = reads.store_call(
        config,
        "record_command_activity_feedback",
        json!({
            "activity_id": activity_id,
            "label": label,
            "recorded_at": now_isoformat()?,
            "schema_version": COMMAND_ACTIVITY_SCHEMA_VERSION,
        }),
    )?
    else {
        return None;
    };
    if answer.get("not_found") == Some(&Value::Bool(true)) {
        return Some((404, json!({"error": "activity_not_found"})));
    }
    // `{"schema_version": ..., **payload}`: a version the store names wins.
    answer
        .entry("schema_version")
        .or_insert_with(|| Value::from(COMMAND_ACTIVITY_SCHEMA_VERSION));
    Some((200, Value::Object(answer)))
}

/// `_read_delete_body`: the JSON object a `DELETE` carries, whatever its
/// `Content-Type`, or `Some(None)` for no body or one that is not an object.
/// `None` for a body only `json.loads` may read.
fn delete_payload(body: &[u8]) -> Option<Option<Map<String, Value>>> {
    if body.is_empty() {
        return Some(None);
    }
    match serde_json::from_slice(body).ok()? {
        Value::Object(payload) => Some(Some(payload)),
        _ => Some(None),
    }
}

/// `DELETE /v1/read-state`: mark one request unread, or clear every mark when
/// `clear_all` is truthy. Any other body changes nothing.
fn clear_read_state(
    payload: Option<&Map<String, Value>>,
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<(u16, Value)> {
    if let Some(payload) = payload {
        if let Some(request_id @ Value::String(_)) = payload.get("request_id") {
            reads.store_call(
                config,
                "mark_request_unread",
                json!({"request_id": request_id}),
            )?;
        } else if !payload.is_empty() && payload.get("clear_all").is_some_and(truthy) {
            reads.store_call(config, "clear_read_state", json!({}))?;
        }
    }
    Some((200, json!({"ok": true})))
}

/// Python's truth value of a JSON value.
fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(value) => *value,
        Value::Number(number) => number.as_f64().is_some_and(|number| number != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(map) => !map.is_empty(),
    }
}

/// `_load_request_body` for a JSON body: `{}` for an empty body or JSON that
/// is not an object. `None` for any body the edge does not read as the daemon
/// does, including one that is not declared JSON.
fn json_payload(request: &Request<'_>, body: &[u8]) -> Option<Map<String, Value>> {
    if body.is_empty() {
        return Some(Map::new());
    }
    if !request
        .single_header("Content-Type")?
        .contains("application/json")
    {
        return None;
    }
    // A body serde rejects, such as `NaN` or a lone surrogate escape, may
    // still be one `json.loads` reads, so the daemon reads it.
    match serde_json::from_slice(body).ok()? {
        Value::Object(payload) => Some(payload),
        _ => Some(Map::new()),
    }
}

/// [`json_payload`] read into Python's values, key order included. A lone
/// surrogate escape, which Python keeps and the edge cannot, goes to the
/// daemon.
pub(super) fn py_payload(request: &Request<'_>, body: &[u8]) -> Option<Vec<(String, PyVal)>> {
    if body.is_empty() {
        return Some(Vec::new());
    }
    if !request
        .single_header("Content-Type")?
        .contains("application/json")
    {
        return None;
    }
    let parsed = pyjson::parse_mapping_lone_surrogates(std::str::from_utf8(body).ok()?).ok()?;
    if parsed.mapped || parsed.collision {
        return None;
    }
    match parsed.value {
        PyVal::Dict(entries) => Some(entries),
        _ => Some(Vec::new()),
    }
}

/// `_handle_read_state_update`. A store call that fails goes to the daemon,
/// which repeats the update: marking a request read again, or unread again,
/// changes nothing a reader sees.
fn update_read_state(
    payload: &Map<String, Value>,
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<(u16, Value)> {
    // `str(payload.get("action") or "mark_read")` names one of the two
    // actions only for those exact strings; every other value marks
    // `request_id` read.
    match payload.get("action").and_then(Value::as_str) {
        Some("mark_all_read") => {
            let Some(Value::Array(request_ids)) = payload.get("request_ids") else {
                return Some((400, json!({"error": "invalid_request_ids"})));
            };
            let request_ids: Vec<&Value> = request_ids.iter().filter(|id| id.is_string()).collect();
            mark_read(&request_ids, config, reads)?;
        }
        Some("mark_unread") => {
            let Some(request_id @ Value::String(_)) = payload.get("request_id") else {
                return Some((400, json!({"error": "invalid_request_id"})));
            };
            reads.store_call(
                config,
                "mark_request_unread",
                json!({"request_id": request_id}),
            )?;
        }
        _ => {
            let Some(request_id @ Value::String(_)) = payload.get("request_id") else {
                return Some((400, json!({"error": "invalid_action"})));
            };
            mark_read(&[request_id], config, reads)?;
        }
    }
    let ids = read_state(config, reads)?;
    Some((200, json!({"ok": true, "ids": ids})))
}

/// `mark_requests_read`. The daemon splits ids into 1 MiB batches; a body the
/// edge reads is far smaller, so its ids always fit one.
fn mark_read(request_ids: &[&Value], config: &ReadConfig, reads: &NativeReads) -> Option<()> {
    if request_ids.is_empty() {
        return Some(());
    }
    reads.store_call(
        config,
        "mark_requests_read",
        json!({"request_ids": request_ids, "now": now_isoformat()?}),
    )?;
    Some(())
}

/// `datetime.now(timezone.utc).isoformat()`, which leaves out a zero
/// fraction just as the shared formatter does.
fn now_isoformat() -> Option<String> {
    let micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .ok()?
        .as_micros();
    micros_to_utc_isoformat(i64::try_from(micros).ok()?, "+00:00")
}
