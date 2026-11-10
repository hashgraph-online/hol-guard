//! The refusals the daemon writes before a route runs: `403 forbidden_origin`
//! for an origin the native policy does not allow, and `401 unauthorized` for
//! a `/v1` or `/v2` request without the auth secret, each with the audit
//! event the daemon records.
//!
//! A standalone daemon has no Python server behind it to write these, so the
//! edge writes them itself for any request it would otherwise replay. A
//! request that carries a dashboard session or a hook challenge proof is
//! never refused here: only the daemon reads those.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::super::auth::{authorize_origin, normalize_origin};
use super::super::http::Request;
use super::{NativeReads, ReadConfig};
use crate::daemon_route_paths::{requires_header_token, route_class};
use crate::guard_store_guard_event::dumps;
use crate::policy_bundle_time::micros_to_utc_isoformat;
use crate::pyjson::PyVal;
use crate::resident_transport::constant_time_eq;

/// `_AUTH_AUDIT_COALESCE_SECONDS`.
const COALESCE: Duration = Duration::from_secs(60);
/// `_AUTH_AUDIT_KEY_LIMIT`.
const KEY_LIMIT: usize = 64;

/// The paths the daemon serves without any check: its static dashboard.
const PUBLIC_PREFIXES: [&str; 2] = ["/assets/", "/static/"];

/// What the edge decided about a request it cannot answer itself.
#[derive(Debug, PartialEq)]
pub(in crate::daemon_edge) enum Refusal {
    ForbiddenOrigin,
    QueryToken,
    Unauthorized,
}

/// The routes whose `GET` refuses a `token` query parameter outright.
fn refuses_query_token(path: &str) -> bool {
    path.starts_with("/v1/discovery/extensions/")
        || path.starts_with("/v2/")
        || matches!(
            path,
            "/v1/desktop/bootstrap" | "/v1/events/stream" | "/v1/command-activity/events"
        )
}

/// The longest body the edge refuses on: every route reads at least this much.
const REFUSED_BODY_LIMIT: usize = 64 * 1024;

/// Whether `_load_request_body` reads `body` without an error, so the
/// daemon's next answer is the caller check's. A body only the route could
/// judge is left to the route.
fn body_reads_as_the_daemon_does(request: &Request<'_>, body: &[u8]) -> bool {
    if request.has_header("Transfer-Encoding") || body.len() > REFUSED_BODY_LIMIT {
        return false;
    }
    let declared = request
        .single_header("Content-Length")
        .and_then(|length| length.trim().parse::<usize>().ok());
    if declared != Some(body.len()) || CHALLENGE_HOOK_PATHS.contains(&request.path) {
        return false;
    }
    let Ok(text) = std::str::from_utf8(body) else {
        return false;
    };
    if request.has_header("Content-Type") && request.single_header("Content-Type").is_none() {
        return false;
    }
    let json = request
        .single_header("Content-Type")
        .is_some_and(|value| value.contains("application/json"));
    !json || serde_json::from_str::<serde_json::Value>(text).is_ok()
}

/// `CHALLENGE_HOOK_PATHS`: hooks a body's identity proof can admit.
const CHALLENGE_HOOK_PATHS: [&str; 2] = ["/v1/hooks/codex", "/v1/hooks/claude-code"];

fn carries_body(request: &Request<'_>) -> bool {
    if request.has_header("Transfer-Encoding") {
        return true;
    }
    request.has_header("Content-Length")
        && request
            .single_header("Content-Length")
            .is_none_or(|length| length.trim() != "0")
}

/// `POST /v1/requests/{id}/approve|block|resume`, whose refusal tells the
/// dashboard how to reconnect.
fn is_decision_path(path: &str) -> bool {
    let parts: Vec<&str> = path.trim_matches('/').split('/').collect();
    parts.len() == 4
        && parts[0] == "v1"
        && parts[1] == "requests"
        && matches!(parts[3], "approve" | "block" | "resume")
}

/// `_build_local_url`.
fn local_url(local: SocketAddr, path: &str) -> String {
    match local.ip() {
        IpAddr::V6(address) => format!("http://[{address}]:{}{path}", local.port()),
        IpAddr::V4(address) => format!("http://{address}:{}{path}", local.port()),
    }
}

fn unauthorized_body(request: &Request<'_>, local: Option<SocketAddr>) -> Value {
    match local.filter(|_| request.method == "POST" && is_decision_path(request.path)) {
        Some(local) => json!({
            "error": "unauthorized",
            "recovery": {
                "code": "session_stale",
                "title": "Your session with the local Guard daemon has expired.",
                "body": "Click the link below to reconnect, then retry your approval.",
                "reconnect_url": local_url(local, "/#/reconnect"),
            },
        }),
        None => json!({"error": "unauthorized"}),
    }
}

fn header_secret_matches(request: &Request<'_>, secret: &[u8]) -> bool {
    let name = format!("X-Guard-{}", "Token");
    request
        .single_header(&name)
        .is_some_and(|presented| constant_time_eq(presented.as_bytes(), secret))
}

/// Whether the daemon would refuse this request before any route ran.
pub(in crate::daemon_edge) fn refusal(
    request: &Request<'_>,
    body: &[u8],
    secret: &[u8],
) -> Option<Refusal> {
    let public = request.path == "/"
        || request.path == "/healthz"
        || PUBLIC_PREFIXES
            .iter()
            .any(|prefix| request.path.starts_with(prefix));
    if !(public && request.method == "GET") && authorize_origin(request).is_none() {
        // A repeated `Origin` header is the daemon's to read.
        return request
            .single_header("Origin")
            .map(|_| Refusal::ForbiddenOrigin);
    }
    if request.has_header("X-Guard-Dashboard-Session")
        || request.has_header("Authorization")
        || request.has_header("X-Guard-Daemon-Proof")
    {
        return None;
    }
    let guarded = match request.method {
        "GET" => request.path.starts_with("/v1/") || request.path.starts_with("/v2/"),
        // A body can carry a dashboard session or a hook challenge proof,
        // which only the route reads.
        // A route outside the `none` class checks the header before it reads
        // the body; any other reads the body first, which only a hook's
        // challenge proof can authorize.
        "POST" | "DELETE" => {
            route_class(request.path) != "none"
                && (request.method == "POST" || !carries_body(request))
                || requires_header_token(request.path)
                    && (!carries_body(request) || body_reads_as_the_daemon_does(request, body))
        }
        _ => false,
    };
    if !guarded {
        return None;
    }
    if request.method != "DELETE"
        && (refuses_query_token(request.path)
            || (request.method == "POST" && request.path.starts_with("/v1/discovery/extensions/")))
        && super::discovery::query_names_token(request.query)
    {
        return Some(Refusal::QueryToken);
    }
    (!header_secret_matches(request, secret)).then_some(Refusal::Unauthorized)
}

/// Why `do_DELETE`'s preamble refused a caller the edge did not authorize:
/// the origin check, then the header token or dashboard session.
pub(in crate::daemon_edge) fn delete_refusal(request: &Request<'_>) -> Refusal {
    if authorize_origin(request).is_none() {
        return Refusal::ForbiddenOrigin;
    }
    Refusal::Unauthorized
}

/// The response for a refusal, after recording its audit event.
pub(in crate::daemon_edge) fn respond(
    request: &Request<'_>,
    refusal: &Refusal,
    local: Option<SocketAddr>,
    config: &ReadConfig,
    reads: &NativeReads,
) -> (u16, Value, Option<String>) {
    let cors_origin = authorize_origin(request).and_then(|caller| caller.cors_origin);
    match refusal {
        Refusal::ForbiddenOrigin => (403, json!({"error": "forbidden_origin"}), None),
        Refusal::QueryToken => {
            let payload = PyVal::Dict(vec![
                ("method".to_owned(), PyVal::Str(request.method.to_owned())),
                ("path".to_owned(), PyVal::Str(request.path.to_owned())),
                (format!("has_query_{}", "token"), PyVal::Bool(true)),
            ]);
            let name = format!("daemon.auth.query_{}_rejected", "token");
            record(&name, &payload, config, reads);
            unauthorized(request, config, reads);
            (401, unauthorized_body(request, local), cors_origin)
        }
        Refusal::Unauthorized => {
            unauthorized(request, config, reads);
            (401, unauthorized_body(request, local), cors_origin)
        }
    }
}

type AuditKey = (
    String,
    String,
    Option<String>,
    Option<String>,
    bool,
    bool,
    bool,
);

struct Window {
    started: Instant,
    suppressed: u64,
    persisted: bool,
}

static WINDOWS: Mutex<Option<HashMap<AuditKey, Window>>> = Mutex::new(None);

/// `_record_auth_audit_event`: one `daemon.auth.unauthorized` row per caller
/// shape a minute, carrying how many it stood for.
fn unauthorized(request: &Request<'_>, config: &ReadConfig, reads: &NativeReads) {
    let origin_header = request
        .single_header("Origin")
        .filter(|origin| !origin.trim().is_empty())
        .map(str::to_owned);
    let origin = origin_header.as_deref().and_then(normalize_origin);
    let key: AuditKey = (
        request.method.to_owned(),
        request.path.to_owned(),
        origin.clone(),
        origin_header.clone(),
        request.has_header("Authorization"),
        request.has_header("X-Guard-Dashboard-Session"),
        request.has_header(&format!("X-Guard-{}", "Token")),
    );
    let now = Instant::now();
    let reported = {
        let mut guard = WINDOWS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let windows = guard.get_or_insert_with(HashMap::new);
        let mut reported = 0;
        if let Some(previous) = windows.get_mut(&key) {
            if now.duration_since(previous.started) < COALESCE && previous.persisted {
                previous.suppressed += 1;
                return;
            }
            reported = previous.suppressed;
        }
        if !windows.contains_key(&key) && windows.len() >= KEY_LIMIT {
            if let Some(oldest) = windows
                .iter()
                .min_by_key(|(_, window)| window.started)
                .map(|(key, _)| key.clone())
            {
                windows.remove(&oldest);
            }
        }
        windows.insert(
            key.clone(),
            Window {
                started: now,
                suppressed: reported,
                persisted: false,
            },
        );
        reported
    };
    let text = |value: Option<String>| value.map_or(PyVal::Null, PyVal::Str);
    let mut entries = vec![
        ("method".to_owned(), PyVal::Str(key.0.clone())),
        ("path".to_owned(), PyVal::Str(key.1.clone())),
        ("origin".to_owned(), text(origin)),
        ("origin_header".to_owned(), text(origin_header)),
        ("has_authorization".to_owned(), PyVal::Bool(key.4)),
        ("has_dashboard_session".to_owned(), PyVal::Bool(key.5)),
        (format!("has_guard_{}", "token"), PyVal::Bool(key.6)),
    ];
    if reported > 0 {
        entries.push((
            "suppressed_count".to_owned(),
            PyVal::Int(reported.to_string()),
        ));
    }
    let persisted = record(
        "daemon.auth.unauthorized",
        &PyVal::Dict(entries),
        config,
        reads,
    );
    let mut guard = WINDOWS
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    if let Some(window) = guard.as_mut().and_then(|windows| windows.get_mut(&key)) {
        if persisted {
            window.suppressed -= reported.min(window.suppressed);
            window.persisted = true;
        } else {
            window.suppressed += 1;
        }
    }
}

/// `audit_persistence.persist`: whether the row landed.
fn record(event_name: &str, payload: &PyVal, config: &ReadConfig, reads: &NativeReads) -> bool {
    let micros = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_micros() as i64);
    let (Some(payload_json), Some(occurred_at)) =
        (dumps(payload), micros_to_utc_isoformat(micros, "+00:00"))
    else {
        return false;
    };
    reads
        .store_write(
            config,
            "add_event",
            json!({
                "event_name": event_name,
                "payload_json": payload_json,
                "occurred_at": occurred_at,
            }),
        )
        .is_ok()
}

#[cfg(all(test, unix))]
#[path = "daemon_edge_refusals_tests.rs"]
mod tests;
