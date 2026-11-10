//! `POST` and `DELETE` routes the daemon edge answers without the Python
//! daemon.
//!
//! The edge takes a write only when the daemon's preamble would pass it with
//! nothing left to decide: the auth token in its one `X-Guard-Token` header
//! (or, on the routes that take one, a session Guard's own dashboard holds),
//! an allowed origin, one plain `Content-Length` and a JSON body the edge reads
//! exactly as `json.loads` would. The daemon reads any other body itself, so a
//! form body, a link-bound or nonce-spending session, a chunked body or JSON
//! that only Python accepts goes to it untouched, with every rejection it
//! writes today.

use std::net::SocketAddr;

use guard_contracts::DaemonFieldV1;
use serde_json::{json, Map, Value};

use super::super::auth::{
    authorize_initialize, authorize_session_write, authorize_token, authorize_write,
    refreshed_session,
};
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
#[path = "daemon_edge_gate_config.rs"]
mod gate_config;
#[path = "daemon_edge_protection_repair.rs"]
mod protection_repair;
#[path = "daemon_edge_reconnect.rs"]
mod reconnect;
#[path = "daemon_edge_resolve.rs"]
mod resolve;
#[path = "daemon_edge_route_calls.rs"]
mod route_calls;
#[path = "daemon_edge_sessions.rs"]
mod sessions;
#[path = "daemon_edge_settings_write.rs"]
mod settings_write;

/// The value a body read, or the daemon's answer for a body it cannot read.
macro_rules! read_body {
    ($read:expr, $cors_origin:expr) => {
        match $read {
            Ok(payload) => payload,
            Err(error) => {
                let (status, body) = error.answer();
                return Some((status, body, $cors_origin, false));
            }
        }
    };
}

pub(super) fn respond(
    request: &Request<'_>,
    body: &[u8],
    local: Option<SocketAddr>,
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<(u16, Value, Option<String>, bool)> {
    if request.method == "POST"
        && matches!(
            request.path,
            "/v1/connect/requests" | "/v1/connect/complete" | "/v1/connect/result"
        )
    {
        // Retired device pairing, refused before any caller check.
        let body = serde_json::json!({
            "error": "legacy_pairing_disabled",
            "message": "Use hol-guard connect for browser OAuth.",
        });
        return Some((410, body, None, false));
    }
    if request.method == "POST" && resolve::owns(request.path) {
        let local = local?;
        let (caller, link_bound) = super::super::auth::authorize_resolve(request, &config.token)?;
        let payload = read_body!(json_payload(request, body), caller.cors_origin.clone());
        reads.report_activity();
        let (status, body, no_store) = resolve::respond(
            request.path,
            &payload,
            local,
            !link_bound,
            resolve::call_library(config),
        )?;
        return Some((status, body, caller.cors_origin, no_store));
    }
    if request.method == "POST" && route_calls::EXTENSION_CONTROL_WRITES.contains(&request.path) {
        let caller = authorize_write(request, &config.token)?;
        let payload = read_body!(json_payload(request, body), caller.cors_origin.clone());
        reads.report_activity();
        let args = route_calls::extension_control_args("POST", request.path);
        let (status, body, no_store) =
            route_calls::respond(args, &payload, route_calls::extension_control(config))?;
        return Some((status, body, caller.cors_origin, no_store));
    }
    if let Some((name, args)) = (request.method == "POST")
        .then(|| route_calls::resident_route(request.path))
        .flatten()
    {
        let caller = authorize_write(request, &config.token)?;
        let payload = read_body!(json_payload(request, body), caller.cors_origin.clone());
        reads.report_activity();
        let (status, body, no_store) =
            route_calls::respond(args, &payload, route_calls::call_resident(config, name))?;
        return Some((status, body, caller.cors_origin, no_store));
    }
    if let Some((name, args)) = (request.method == "POST")
        .then(|| route_calls::route(request.path))
        .flatten()
    {
        let caller = authorize_write(request, &config.token)?;
        let payload = read_body!(json_payload(request, body), caller.cors_origin.clone());
        reads.report_activity();
        let (status, body, no_store) =
            route_calls::respond(args, &payload, route_calls::call_library(config, name))?;
        return Some((status, body, caller.cors_origin, no_store));
    }
    if request.method == "POST"
        && matches!(
            request.path,
            "/v1/update/reconnect/challenge" | "/v1/update/reconnect/verify"
        )
    {
        // The dashboard reconnects before it holds the header key, so these
        // run on the origin check alone, as the daemon runs them.
        if request.has_header("Transfer-Encoding")
            || request.has_header("X-Guard-Dashboard-Session")
            || request.has_header("Authorization")
        {
            return None;
        }
        let local = local?;
        let caller = super::super::auth::authorize_origin(request)?;
        let payload = read_body!(json_payload(request, body), caller.cors_origin.clone());
        reads.report_activity();
        let daemon = reconnect::Daemon {
            guard_home: &config.guard_home,
            local,
            pid: reads.daemon_pid(),
            state_id: reads.state_id(),
        };
        let (status, body) = if request.path.ends_with("/challenge") {
            reconnect::challenge(&payload, &daemon)
        } else {
            reconnect::verify(&payload, &daemon)
        };
        return Some((status, body, caller.cors_origin, true));
    }
    if request.method == "POST" && request.path == "/v1/update/reconnect/prepare" {
        let caller = authorize_write(request, &config.token)?;
        read_body!(json_payload(request, body), caller.cors_origin.clone());
        reads.report_activity();
        let (status, body) = reconnect_prepare(&config.guard_home);
        return Some((status, body, caller.cors_origin, true));
    }
    if request.method == "POST" && request.path == "/v1/notifications/setup" {
        let local = local?;
        let caller = authorize_write(request, &config.token)?;
        read_body!(json_payload(request, body), caller.cors_origin.clone());
        reads.report_activity();
        let host = match local.ip() {
            std::net::IpAddr::V6(ip) => format!("[{ip}]"),
            std::net::IpAddr::V4(ip) => ip.to_string(),
        };
        let approval_url = format!(
            "http://{host}:{}/approvals/notification-preview",
            local.port()
        );
        let body = crate::desktop_notification::setup_reply(
            std::path::Path::new(&config.guard_home),
            &approval_url,
        );
        return Some((200, body, caller.cors_origin, false));
    }
    // A wrong daemon credential is refused before any route runs.
    if request.method == "POST"
        && legacy_cloud_handoff(request.path)
        && (super::super::auth::authorize_write(request, &config.token).is_some()
            || !request.has_header("X-Guard-Token"))
    {
        // The retired handoff does nothing, so it answers without a token,
        // as the Python daemon did.
        let caller = super::super::auth::authorize_origin(request)?;
        read_body!(json_payload(request, body), caller.cors_origin.clone());
        reads.report_activity();
        let body = serde_json::json!({
            "error": "legacy_cloud_handoff_disabled",
            "message": "Use hol-guard connect for browser OAuth.",
        });
        return Some((410, body, caller.cors_origin, false));
    }
    if let Some(route) = sessions::Route::parse(request.method, request.path) {
        if request.has_header("Transfer-Encoding") {
            return None;
        }
        let initialize = matches!(route, sessions::Route::Initialize);
        let (caller, include_sessions) = if initialize {
            authorize_initialize(request, &config.token)?
        } else {
            (authorize_session_write(request, &config.token)?, true)
        };
        let payload = read_body!(py_payload(request, body), caller.cors_origin.clone());
        reads.report_activity();
        let (status, mut answer) =
            sessions::respond(&route, &payload, include_sessions, config, reads)?;
        if initialize && status == 200 {
            let surface = sessions::initialize_surface(&payload);
            if let (Some(fields), Some(refreshed)) = (
                answer.as_object_mut(),
                refreshed_session(request, &config.token, &surface),
            ) {
                fields.insert(
                    "dashboard_session_token".to_owned(),
                    Value::String(refreshed),
                );
            }
        }
        return Some((status, answer, caller.cors_origin, false));
    }
    if let Some(route) = gate_config::Route::parse(request.method, request.path) {
        let caller = authorize_token(request, &config.token)?;
        let payload = read_body!(json_payload(request, body), caller.cors_origin.clone());
        reads.report_activity();
        return gate_config::respond(&route, &payload, config)
            .map(|(status, body)| (status, body, caller.cors_origin, false));
    }
    if request.method == "POST"
        && matches!(
            request.path,
            "/v1/settings" | "/v1/settings/import" | "/v1/settings/reset"
        )
    {
        let caller = authorize_token(request, &config.token)?;
        let payload = read_body!(json_payload(request, body), caller.cors_origin.clone());
        let answer = if request.path == "/v1/settings/reset" {
            reads.report_activity();
            settings_write::reset(&payload, config, reads)
        } else {
            let entries = read_body!(py_payload(request, body), caller.cors_origin.clone());
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
    if request.method == "DELETE" {
        return delete(request, body, config, reads);
    }
    if !matches!(
        route,
        (
            "POST",
            "/v1/read-state"
                | "/v1/command-activity/feedback"
                | "/v1/requests/clear"
                | "/v1/plugins/updates/dismiss"
        )
    ) {
        return control_post(request, body, config, reads);
    }
    let caller = authorize_token(request, &config.token)?;
    if route.1 == "/v1/plugins/updates/dismiss" {
        let payload = read_body!(json_payload(request, body), caller.cors_origin.clone());
        reads.report_activity();
        let (status, body) = plugin_update_dismiss(&payload, config);
        return Some((status, body, caller.cors_origin, true));
    }
    let answer = match route {
        ("POST", "/v1/read-state") => {
            let payload = read_body!(json_payload(request, body), caller.cors_origin.clone());
            reads.report_activity();
            update_read_state(&payload, config, reads)
        }
        ("POST", "/v1/requests/clear") => {
            let payload = read_body!(json_payload(request, body), caller.cors_origin.clone());
            reads.report_activity();
            requests_clear(&payload, config, reads)
        }
        _ => {
            let payload = read_body!(json_payload(request, body), caller.cors_origin.clone());
            reads.report_activity();
            command_activity_feedback(&payload, config, reads)
        }
    };
    answer.map(|(status, body)| (status, body, caller.cors_origin, false))
}

/// Every other control `POST`: the daemon's control handlers answer it in
/// the resident library process, with the server state they share loaded
/// from the Guard home, and `404` a path none of them names. Hook posts are
/// the hook path's, never a control handler's.
fn control_post(
    request: &Request<'_>,
    body: &[u8],
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<(u16, Value, Option<String>, bool)> {
    if request.method != "POST" || request.path.starts_with("/v1/hooks/") {
        return None;
    }
    // The header check runs before the body is read; only a session the
    // verdict could admit on its payload waits for the body.
    let header_caller = authorize_write(request, &config.token);
    if header_caller.is_none() && !super::super::auth::session_may_read_payload(request) {
        return None;
    }
    let origin = super::super::auth::authorize_origin(request)?;
    let payload = read_body!(json_payload(request, body), origin.cors_origin.clone());
    let caller = match header_caller {
        Some(caller) => caller,
        None => super::super::auth::authorize_write_with(request, &config.token, &payload)?,
    };
    if request.path == "/v1/daemon/repair" {
        reads.report_activity();
        let answer = crate::daemon_manage::repair_from_daemon(
            std::path::Path::new(&config.guard_home),
            config.user_home.as_deref().unwrap_or_default(),
        );
        return Some(match answer {
            Some(body) => (200, body, caller.cors_origin, false),
            None => (DROPPED, Value::Null, caller.cors_origin, false),
        });
    }
    let port = reads.published_state()?.get("port")?.as_u64()?;
    reads.report_activity();
    if request.path == "/v1/protection/repair" {
        let (status, body) = protection_repair::protection_repair(&payload, config, port)?;
        return Some((status, body, caller.cors_origin, false));
    }
    let mut args = serde_json::Map::new();
    args.insert("path".to_owned(), Value::from(request.path));
    args.insert("port".to_owned(), Value::from(port));
    args.insert("daemon_pid".to_owned(), Value::from(reads.daemon_pid()));
    args.insert(
        "home_dir".to_owned(),
        config.user_home.as_deref().map_or(Value::Null, Value::from),
    );
    let (status, body, no_store) = route_calls::respond(
        args,
        &payload,
        route_calls::call_resident(config, "route.control_post"),
    )?;
    Some((status, body, caller.cors_origin, no_store))
}

/// Every `DELETE`, as `do_DELETE` answered it: the header token or, on a
/// session path, a dashboard session, then the
/// three routes, then `404`. `None` only for a caller the edge refuses, which
/// [`super::refusals::delete_refusal`] answers.
fn delete(
    request: &Request<'_>,
    body: &[u8],
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<(u16, Value, Option<String>, bool)> {
    let caller = authorize_write(request, &config.token)?;
    // `do_DELETE` read only a `Content-Length` body, so a chunked one is none.
    let body = if request.has_header("Transfer-Encoding") {
        &[][..]
    } else {
        body
    };
    let answer = match request.path {
        "/v1/command-activity" => {
            reads.report_activity();
            clear_command_activity(body, config, reads)
        }
        "/v1/read-state" => {
            reads.report_activity();
            clear_read_state(delete_payload(body).as_ref(), config, reads)
        }
        "/v1/evidence" => {
            reads.report_activity();
            reads
                .store_call(config, "clear_evidence", json!({}))
                .and_then(|deleted| deleted.as_i64())
                .map(|deleted| (200, json!({"deleted": deleted})))
        }
        _ => return Some((404, json!({"error": "not_found"}), None, false)),
    };
    // The store could not answer once the route ran: the connection closes.
    let (status, body) = answer.unwrap_or((DROPPED, Value::Null));
    Some((status, body, caller.cors_origin, false))
}

/// `_handle_requests_clear`: the native option check, the approval gate, then
/// `clear_approval_requests`.
/// `POST /v1/update/reconnect/prepare`: one stored browser verifier for the
/// restart a dashboard update makes.
fn reconnect_prepare(guard_home: &str) -> (u16, Value) {
    let answer =
        crate::dashboard_reconnect::dispatch(&serde_json::json!({"op": "prepare"}), guard_home);
    match answer
        .ok()
        .and_then(|answer| answer.get("authorization").cloned())
    {
        Some(authorization @ Value::Object(_)) => (200, authorization),
        _ => (
            503,
            serde_json::json!({
                "error": "dashboard_reconnect_unavailable",
                "reason_code": "dashboard_reconnect_identity_unavailable",
            }),
        ),
    }
}

/// `POST /v1/apps/{app}/cloud/{action}`: the old Cloud handoff, now refused.
fn legacy_cloud_handoff(path: &str) -> bool {
    crate::daemon_route_paths::route_class(path) == "none"
        && matches!(
            crate::daemon_route_paths::segments(path).as_slice(),
            ["v1", "apps", _, "cloud", _]
        )
}

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
/// `Content-Type`; `None` for no body or one that is not an object.
fn delete_payload(body: &[u8]) -> Option<Map<String, Value>> {
    match serde_json::from_slice(body) {
        Ok(Value::Object(payload)) => Some(payload),
        _ => None,
    }
}

/// `DELETE /v1/command-activity`: the typed confirmation, the approval gate,
/// then one transaction that removes command evidence and what derives from it.
fn clear_command_activity(
    body: &[u8],
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<(u16, Value)> {
    let payload = match serde_json::from_slice::<Value>(body) {
        Ok(Value::Object(payload)) if !body.is_empty() => payload,
        _ => return Some((400, json!({"error": "invalid_request"}))),
    };
    if payload.get("confirm").and_then(Value::as_str) != Some(CLEAR_COMMAND_ACTIVITY) {
        return Some((
            400,
            json!({"error": "confirmation_required", "confirm": CLEAR_COMMAND_ACTIVITY}),
        ));
    }
    match gate::require_high_risk("evidence_clear", &payload, config)? {
        gate::Gate::Refused(status, refusal) => Some((status, Value::Object(refusal))),
        gate::Gate::Passed(_) => {
            // The gate has run, so a failed write closes the connection.
            let Some(Value::Object(cleared)) =
                reads.store_call(config, "clear_command_activity_evidence", json!({}))
            else {
                return Some((DROPPED, Value::Null));
            };
            let mut answer = Map::new();
            answer.insert(
                "schema_version".to_owned(),
                Value::from(COMMAND_ACTIVITY_DIAGNOSTICS_SCHEMA_VERSION),
            );
            answer.extend(cleared);
            Some((200, Value::Object(answer)))
        }
    }
}

const CLEAR_COMMAND_ACTIVITY: &str = "clear-command-activity";
/// `COMMAND_ACTIVITY_DIAGNOSTICS_SCHEMA_VERSION`.
const COMMAND_ACTIVITY_DIAGNOSTICS_SCHEMA_VERSION: &str = "guard.command-activity-diagnostics.v1";

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

/// `_load_request_body` read into JSON values: `{}` for an empty body or
/// JSON that is not an object, a form body's last value per name, and the
/// daemon's 400 for a body it cannot read.
fn json_payload(request: &Request<'_>, body: &[u8]) -> Result<Map<String, Value>, BodyError> {
    let entries = py_payload(request, body)?;
    match PyVal::Dict(entries).to_json() {
        Some(Value::Object(payload)) => Ok(payload),
        _ => Err(BodyError("invalid_request_body")),
    }
}

/// The error `_load_request_body` names for a body it cannot read, answered
/// with status 400.
#[derive(Debug, PartialEq)]
pub(super) struct BodyError(pub(super) &'static str);

impl BodyError {
    /// The daemon's answer for this error.
    pub(super) fn answer(&self) -> (u16, Value) {
        (400, json!({ "error": self.0 }))
    }
}

/// `_load_request_body` read into Python's values, key order included: a
/// JSON object, `{}` for other JSON, or a form body's last value per name. A
/// lone surrogate escape keeps a distinct private-use character, as Python
/// keeps a distinct surrogate.
pub(super) fn py_payload(
    request: &Request<'_>,
    body: &[u8],
) -> Result<Vec<(String, PyVal)>, BodyError> {
    if request.has_header("Transfer-Encoding") {
        return Err(BodyError("unsupported_transfer_encoding"));
    }
    if body.is_empty() {
        return Ok(Vec::new());
    }
    let Ok(text) = std::str::from_utf8(body) else {
        return Err(BodyError("invalid_request_body"));
    };
    let json = request
        .first_header("Content-Type")
        .is_some_and(|value| value.contains("application/json"));
    if !json {
        let mut entries: Vec<(String, PyVal)> = Vec::new();
        for (name, value) in super::super::http::parse_qs(text) {
            match entries.iter_mut().find(|(key, _)| *key == name) {
                Some(entry) => entry.1 = PyVal::Str(value),
                None => entries.push((name, PyVal::Str(value))),
            }
        }
        return Ok(entries);
    }
    match pyjson::parse_mapping_lone_surrogates(text) {
        Ok(parsed) => Ok(match parsed.value {
            PyVal::Dict(entries) => entries,
            _ => Vec::new(),
        }),
        Err(_) => Err(BodyError("invalid_request_body")),
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
