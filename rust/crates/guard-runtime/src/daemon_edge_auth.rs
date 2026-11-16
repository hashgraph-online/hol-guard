//! Who may read through the daemon edge, decided as the daemon decides it.
//!
//! The daemon's Python server lets a `/v1` read through for its auth token,
//! or for a signed dashboard session the dashboard holds instead, and checks
//! any `Origin` first. The edge repeats those checks with the same native
//! origin and session policy. Its answer is only ever "the daemon would let
//! this read through" or "ask the daemon": a header it cannot read the way
//! the daemon reads it, a session whose verdict spends a single-use nonce, or
//! anything that fails, goes back to the daemon, which keeps every rejection
//! and audit record it writes today.

use std::time::{SystemTime, UNIX_EPOCH};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use guard_contracts::{
    DaemonListFieldV1, DaemonRoutePayloadV1, DaemonSessionClaimsV1, DaemonSessionPayloadV1,
};
use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha2::Sha256;

use super::http::Request;
use crate::daemon_route_paths::{session_path, supply_chain_claim_action};
use crate::daemon_route_session::{origin_decision, session_authorize, SessionRequest};
use crate::guard_store_json::{aware_epoch_micros, py_strip};
use crate::hook_env_stamp::json_string;
use crate::policy_bundle_time::micros_to_utc_isoformat;
use crate::resident_transport::constant_time_eq;

const SESSION_PREFIX: &str = "gld1";
const SESSION_AUDIENCE: &str = "guard-local-daemon";
/// The surfaces whose sessions the daemon checks against the path alone.
const DASHBOARD_SURFACES: [&str; 3] = ["approval-center", "dashboard", "cloud-dashboard"];
/// A session this close to its expiry goes to the daemon, so the edge never
/// honors one the daemon's own clock has already ended.
const EXPIRY_MARGIN_MICROS: i128 = 1_000_000;
const SESSION_VERSION: &str = "guard-local-daemon-session.v1";
const STARTED_AT_CLAIM: &str = "session_started_at";
const REPAIR_SURFACE: &str = "protection-repair";
/// How long a refreshed session lasts, at most.
const SESSION_TTL_MICROS: i128 = 12 * 60 * 60 * 1_000_000;
/// How long after it was first opened a session may still be refreshed.
const SESSION_MAX_AGE_MICROS: i128 = 7 * 24 * 60 * 60 * 1_000_000;
/// How long after it expired a session may still be refreshed.
const REFRESH_GRACE_MICROS: i128 = 7 * 24 * 60 * 60 * 1_000_000;

/// A caller the daemon would let read: the origin to name in the CORS
/// headers when the request carried one.
pub(super) struct Caller {
    pub(super) cors_origin: Option<String>,
}

pub(super) fn authorize(request: &Request<'_>, token: &[u8]) -> Option<Caller> {
    let caller = allowed_origin(request)?;
    if token_matches(request, token)? {
        return Some(caller);
    }
    session_allows(request, token, caller.cors_origin.as_deref()).then_some(caller)
}

/// A caller the daemon would let write: an allowed origin and its auth token,
/// or a session whose verdict lets it use the path, as `_header_token_is_valid`
/// decided; a nonce the verdict spends is honored once.
pub(super) fn authorize_token(request: &Request<'_>, token: &[u8]) -> Option<Caller> {
    let caller = allowed_origin(request)?;
    if token_matches(request, token)? {
        return Some(caller);
    }
    session_allows(request, token, caller.cors_origin.as_deref()).then_some(caller)
}

/// A caller of a `POST` or `DELETE`: an allowed origin and either its auth
/// token or a session whose verdict lets it write the path.
pub(super) fn authorize_write(request: &Request<'_>, token: &[u8]) -> Option<Caller> {
    let caller = allowed_origin(request)?;
    if token_matches(request, token)? {
        return Some(caller);
    }
    (matches!(request.method, "POST" | "DELETE")
        && session_allows(request, token, caller.cors_origin.as_deref()))
    .then_some(caller)
}

/// A caller of an approval decision, and whether it holds a session opened
/// from an approval link: such a session settles only its own request, as
/// `_request_holds_link_bound_session` decided.
pub(super) fn authorize_resolve(request: &Request<'_>, token: &[u8]) -> Option<(Caller, bool)> {
    let caller = allowed_origin(request)?;
    let bound = holds_link_bound_session(request, token);
    if token_matches(request, token)? {
        return Some((caller, bound));
    }
    if request.method != "POST" || !session_path(request.method, request.path) {
        return None;
    }
    let now = now_micros();
    session_candidates(request)?
        .into_iter()
        .any(|candidate| {
            let Some(claims) = verified_claims(candidate, token, now) else {
                return false;
            };
            let verdict = session_authorize(&SessionRequest {
                method: request.method,
                path: request.path,
                claims: &claims,
                payload: None,
                header_nonce: None,
                request_origin: caller.cors_origin.as_deref(),
            });
            matches!(
                verdict,
                DaemonRoutePayloadV1::SessionAuthorize {
                    allowed: true,
                    consume_nonce: None,
                }
            )
        })
        .then_some((caller, bound))
}

/// `_request_holds_link_bound_session`: any presented session, refreshable,
/// from a dashboard surface and bound to a request.
fn holds_link_bound_session(request: &Request<'_>, token: &[u8]) -> bool {
    let now = now_micros();
    session_candidates(request).is_some_and(|candidates| {
        candidates.into_iter().any(|candidate| {
            signed_payload(candidate, token, now - REFRESH_GRACE_MICROS).is_some_and(|claims| {
                text(&claims, "surface").is_some_and(|surface| {
                    DASHBOARD_SURFACES.contains(&surface.as_str()) || surface == REPAIR_SURFACE
                }) && claims
                    .get("request_id")
                    .is_some_and(|bound| !bound.is_null())
            })
        })
    })
}

/// A caller of `POST /v1/initialize`, which the daemon opens to any allowed
/// origin, and whether it also holds the auth token, which alone lets it see
/// the newest sessions: the route is no session path, so `_header_token_is_valid`
/// never takes a dashboard session for it.
pub(super) fn authorize_initialize(request: &Request<'_>, token: &[u8]) -> Option<(Caller, bool)> {
    let caller = allowed_origin(request)?;
    let holds_token = token_matches(request, token).unwrap_or(false);
    Some((caller, holds_token))
}

/// A caller of a session or operation write: an allowed origin and either
/// the auth token or a dashboard session whose verdict lets it write `path`
/// without spending a nonce, as `_header_token_is_valid` decides.
pub(super) fn authorize_session_write(request: &Request<'_>, token: &[u8]) -> Option<Caller> {
    let caller = allowed_origin(request)?;
    if token_matches(request, token)? {
        return Some(caller);
    }
    if !session_path(request.method, request.path) {
        return None;
    }
    let candidates = session_candidates(request)?;
    let now = now_micros();
    candidates
        .into_iter()
        .any(|candidate| {
            let Some(claims) = verified_claims(candidate, token, now) else {
                return false;
            };
            let verdict = session_authorize(&SessionRequest {
                method: request.method,
                path: request.path,
                claims: &claims,
                payload: None,
                header_nonce: None,
                request_origin: caller.cors_origin.as_deref(),
            });
            matches!(
                verdict,
                DaemonRoutePayloadV1::SessionAuthorize {
                    allowed: true,
                    consume_nonce: None,
                }
            )
        })
        .then_some(caller)
}

/// `_refresh_dashboard_session_token`: a new session for the dashboard
/// session the request presents, signed as `build_local_dashboard_session_token`
/// signs one, or `None` when it presents none the daemon would refresh.
///
/// A session that expired within the grace window still refreshes, but never
/// past seven days from when it was first opened, and one bound to a single
/// request ends with the link that opened it.
pub(super) fn refreshed_session(
    request: &Request<'_>,
    token: &[u8],
    surface: &str,
) -> Option<String> {
    let now = now_micros();
    let claims = session_candidates(request)?
        .into_iter()
        .find_map(|candidate| {
            let claims = signed_payload(candidate, token, now - REFRESH_GRACE_MICROS)?;
            let refreshable = text(&claims, "surface").is_some_and(|surface| {
                DASHBOARD_SURFACES.contains(&surface.as_str()) || surface == REPAIR_SURFACE
            });
            refreshable.then_some(claims)
        })?;
    if claims
        .get("request_id")
        .is_some_and(|bound| !bound.is_null())
    {
        return None;
    }
    let started_at = match text(&claims, STARTED_AT_CLAIM) {
        Some(started_at) => started_at,
        None => {
            let expires_at = aware_epoch_micros(&text(&claims, "expires_at")?)?;
            micros_to_utc_isoformat(
                i64::try_from(expires_at - SESSION_TTL_MICROS).ok()?,
                "+00:00",
            )?
        }
    };
    let remaining = aware_epoch_micros(&started_at)? + SESSION_MAX_AGE_MICROS - now;
    if remaining < 1_000_000 {
        return None;
    }
    let refreshed_surface = if text(&claims, "surface").as_deref() == Some(REPAIR_SURFACE) {
        REPAIR_SURFACE
    } else if DASHBOARD_SURFACES.contains(&surface) {
        surface
    } else {
        "dashboard"
    };
    let ttl = (SESSION_TTL_MICROS / 1_000_000)
        .min(remaining / 1_000_000)
        .max(1);
    signed_session(token, refreshed_surface, now + ttl * 1_000_000, &started_at)
}

/// `build_local_dashboard_session_token` with no extra claims.
fn signed_session(
    token: &[u8],
    surface: &str,
    expires_at: i128,
    started_at: &str,
) -> Option<String> {
    let expires_at = micros_to_utc_isoformat(i64::try_from(expires_at).ok()?, "+00:00")?;
    let field = |text: &str| json_string(text, true, false);
    let payload = format!(
        "{{\"aud\":{},\"version\":{},\"surface\":{},\"expires_at\":{},\"{STARTED_AT_CLAIM}\":{}}}",
        field(SESSION_AUDIENCE),
        field(SESSION_VERSION),
        field(surface),
        field(&expires_at),
        field(started_at),
    );
    let encoded = URL_SAFE_NO_PAD.encode(payload.as_bytes());
    let mut mac = Hmac::<Sha256>::new_from_slice(token).ok()?;
    mac.update(encoded.as_bytes());
    let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    Some(format!("{SESSION_PREFIX}.{encoded}.{signature}"))
}

/// A caller on a route the daemon opens to any allowed origin.
pub(super) fn authorize_origin(request: &Request<'_>) -> Option<Caller> {
    allowed_origin(request)
}

/// Whether the request carries the auth token, or `None` when it repeats the
/// header, which the edge does not read the way the daemon does.
fn token_matches(request: &Request<'_>, token: &[u8]) -> Option<bool> {
    if !request.has_header("X-Guard-Token") {
        return Some(false);
    }
    let presented = request.single_header("X-Guard-Token")?;
    Some(constant_time_eq(presented.as_bytes(), token))
}

/// `_origin_is_allowed_for_request`: no `Origin`, or one the native policy
/// allows for the path.
fn allowed_origin(request: &Request<'_>) -> Option<Caller> {
    let cors_origin = if request.has_header("Origin") {
        let origin = normalize_origin(request.single_header("Origin")?)?;
        let DaemonRoutePayloadV1::Origin { allowed: true, .. } =
            origin_decision(&origin, request.path)
        else {
            return None;
        };
        Some(origin)
    } else {
        None
    };
    Some(Caller { cors_origin })
}

/// `_normalize_origin`, for the origins the edge reads exactly as Python's
/// `urlparse` does: a lowercase `http` or `https` scheme, a plain host and an
/// optional decimal port, with nothing after but one optional `/`.
pub(super) fn normalize_origin(raw: &str) -> Option<String> {
    let text = py_strip(raw);
    let (scheme, rest) = text.split_once("://")?;
    let default_port = match scheme {
        "http" => 80,
        "https" => 443,
        _ => return None,
    };
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
        let (address, tail) = inner.split_once(']')?;
        if address.is_empty()
            || !address
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || matches!(byte, b':' | b'.'))
        {
            return None;
        }
        let port = match tail {
            "" => None,
            tail => Some(tail.strip_prefix(':')?),
        };
        (format!("[{}]", address.to_ascii_lowercase()), port)
    } else {
        let (host, port) = match authority.split_once(':') {
            Some((host, port)) => (host, Some(port)),
            None => (authority, None),
        };
        if host.is_empty()
            || !host
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        {
            return None;
        }
        (host.to_ascii_lowercase(), port)
    };
    let port = match port {
        None => None,
        Some(digits) => {
            if digits.is_empty() || digits.len() > 5 || !digits.bytes().all(|b| b.is_ascii_digit())
            {
                return None;
            }
            let port: u32 = digits.parse().ok()?;
            if port > 65_535 {
                return None;
            }
            Some(port)
        }
    };
    let suffix = match port {
        Some(port) if port != default_port => format!(":{port}"),
        _ => String::new(),
    };
    Some(format!("{scheme}://{host}{suffix}"))
}

/// Whether a dashboard session the request presents lets it read `path`
/// without spending a nonce.
pub(super) fn session_allows(request: &Request<'_>, token: &[u8], origin: Option<&str>) -> bool {
    session_allows_with(request, token, origin, None)
}

/// A caller of a `POST` whose session verdict reads the body, as
/// `_header_token_is_valid(payload=...)` decided: the auth token, or a session
/// the verdict lets write the path with this payload.
pub(super) fn authorize_write_with(
    request: &Request<'_>,
    token: &[u8],
    payload: &Map<String, Value>,
) -> Option<Caller> {
    let caller = allowed_origin(request)?;
    if token_matches(request, token)? {
        return Some(caller);
    }
    let payload = session_payload(payload);
    session_allows_with(
        request,
        token,
        caller.cors_origin.as_deref(),
        Some(&payload),
    )
    .then_some(caller)
}

/// Whether a `POST` that failed the header check may still be admitted by a
/// session verdict that reads its body.
pub(super) fn session_may_read_payload(request: &Request<'_>) -> bool {
    // An action-scoped session (a supply-chain action or a cloud app action)
    // is decided on the body's workspace, location and origin.
    request.method == "POST"
        && (session_path(request.method, request.path)
            || supply_chain_claim_action(request.path).is_some()
            || cloud_app_action_path(request.path))
}

fn cloud_app_action_path(path: &str) -> bool {
    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    parts.len() == 3 && parts[..2] == ["v1", "apps"]
}

/// The body fields a session verdict reads, as `native_session_authorize`
/// projected them.
fn session_payload(payload: &Map<String, Value>) -> DaemonSessionPayloadV1 {
    let text = |key: &str| {
        payload
            .get(key)
            .and_then(Value::as_str)
            .map(py_strip)
            .filter(|value| !value.is_empty())
            .map(str::to_owned)
    };
    let managers = match payload.get("managers") {
        None | Some(Value::Null) => DaemonListFieldV1::Absent,
        Some(Value::Array(items)) if items.iter().all(Value::is_string) => {
            DaemonListFieldV1::Strings {
                values: items
                    .iter()
                    .filter_map(|item| item.as_str().map(str::to_owned))
                    .collect(),
            }
        }
        Some(_) => DaemonListFieldV1::Invalid,
    };
    DaemonSessionPayloadV1 {
        harness: text("harness"),
        workspace_id: text("workspace_id"),
        workspace_id_camel: text("workspaceId"),
        location_id: text("location_id"),
        location_id_camel: text("locationId"),
        daemon_origin: text("daemon_origin"),
        daemon_origin_camel: text("daemonOrigin"),
        dashboard_session_nonce: text("dashboard_session_nonce"),
        managers,
    }
}

fn session_allows_with(
    request: &Request<'_>,
    token: &[u8],
    origin: Option<&str>,
    payload: Option<&DaemonSessionPayloadV1>,
) -> bool {
    if !session_path(request.method, request.path) && !session_may_read_payload(request) {
        return false;
    }
    let Some(candidates) = session_candidates(request) else {
        return false;
    };
    let header_nonce = if request.has_header("X-Guard-Dashboard-Nonce") {
        let Some(nonce) = request.single_header("X-Guard-Dashboard-Nonce") else {
            return false;
        };
        Some(py_strip(nonce)).filter(|nonce| !nonce.is_empty())
    } else {
        None
    };
    let now = now_micros();
    candidates.into_iter().any(|candidate| {
        let Some(claims) = verified_claims(candidate, token, now) else {
            return false;
        };
        let verdict = session_authorize(&SessionRequest {
            method: request.method,
            path: request.path,
            claims: &claims,
            payload,
            header_nonce,
            request_origin: origin,
        });
        let DaemonRoutePayloadV1::SessionAuthorize {
            allowed,
            consume_nonce,
        } = verdict
        else {
            return false;
        };
        if allowed && consume_nonce.is_some_and(|nonce| !consume_session_nonce(&nonce)) {
            return false;
        }
        allowed
    })
}

/// `_consume_dashboard_session_nonce`: a nonce a session verdict spends is
/// honored once in ten minutes.
fn consume_session_nonce(nonce: &str) -> bool {
    use std::collections::HashMap;
    use std::sync::{LazyLock, Mutex};
    use std::time::{Duration, Instant};

    static SEEN: LazyLock<Mutex<HashMap<String, Instant>>> =
        LazyLock::new(|| Mutex::new(HashMap::new()));
    let now = Instant::now();
    let mut seen = SEEN.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
    seen.retain(|_, at| now.duration_since(*at) < Duration::from_secs(600));
    if seen.contains_key(nonce) {
        return false;
    }
    seen.insert(nonce.to_owned(), now);
    true
}

/// The session tokens the daemon would try, in its order, or `None` when a
/// header it reads is repeated.
fn session_candidates<'a>(request: &Request<'a>) -> Option<Vec<&'a str>> {
    let mut candidates = Vec::new();
    for name in ["X-Guard-Dashboard-Session", "Authorization"] {
        if !request.has_header(name) {
            continue;
        }
        let value = request.single_header(name)?;
        let candidate = if name == "Authorization" {
            let Some(scheme) = value.get(..7) else {
                continue;
            };
            if !scheme.eq_ignore_ascii_case("bearer ") {
                continue;
            }
            py_strip(&value[7..])
        } else {
            value
        };
        if !py_strip(candidate).is_empty() {
            candidates.push(candidate);
        }
    }
    Some(candidates)
}

/// The claims of a session token the daemon's auth token signed, whose
/// audience is the local daemon and which has not expired.
/// The decoded claims of a session the auth token signed, for the local
/// daemon, and not about to expire.
fn verified_payload(session: &str, token: &[u8], now: i128) -> Option<Map<String, Value>> {
    signed_payload(session, token, now + EXPIRY_MARGIN_MICROS)
}

/// The claims of a session the auth token signed for the local daemon whose
/// expiry falls after `expiry_floor`.
fn signed_payload(session: &str, token: &[u8], expiry_floor: i128) -> Option<Map<String, Value>> {
    let mut parts = session.split('.');
    let (prefix, payload, signature) = (parts.next()?, parts.next()?, parts.next()?);
    if parts.next().is_some() || prefix != SESSION_PREFIX || payload.is_empty() {
        return None;
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(token).ok()?;
    mac.update(payload.as_bytes());
    let expected = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
    if !constant_time_eq(signature.as_bytes(), expected.as_bytes()) {
        return None;
    }
    let decoded = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let Value::Object(claims) = serde_json::from_slice(&decoded).ok()? else {
        return None;
    };
    if text(&claims, "aud").as_deref() != Some(SESSION_AUDIENCE) {
        return None;
    }
    let expires_at = aware_epoch_micros(claims.get("expires_at")?.as_str()?)?;
    if expires_at <= expiry_floor {
        return None;
    }
    Some(claims)
}

fn verified_claims(session: &str, token: &[u8], now: i128) -> Option<DaemonSessionClaimsV1> {
    let claims = verified_payload(session, token, now)?;
    Some(DaemonSessionClaimsV1 {
        surface: text(&claims, "surface"),
        action_path: text(&claims, "action_path"),
        harness: text(&claims, "harness"),
        nonce: text(&claims, "nonce"),
        workspace_id: text(&claims, "workspace_id"),
        workspace_id_camel: text(&claims, "workspaceId"),
        location_id: text(&claims, "location_id"),
        location_id_camel: text(&claims, "locationId"),
        daemon_origin: text(&claims, "daemon_origin"),
        daemon_origin_camel: text(&claims, "daemonOrigin"),
        allowed_read_paths: strings(&claims, "allowed_read_paths"),
        allowed_action_paths: strings(&claims, "allowed_action_paths"),
        managers: strings(&claims, "managers"),
        request_id: text(&claims, "request_id"),
    })
}

/// A claim's text, stripped, or `None` when absent, not text or blank.
fn text(claims: &Map<String, Value>, key: &str) -> Option<String> {
    let value = py_strip(claims.get(key)?.as_str()?);
    (!value.is_empty()).then(|| value.to_owned())
}

/// The text items of a list claim, or `None` when it is not a list.
fn strings(claims: &Map<String, Value>, key: &str) -> Option<Vec<String>> {
    Some(
        claims
            .get(key)?
            .as_array()?
            .iter()
            .filter_map(|item| item.as_str().map(str::to_owned))
            .collect(),
    )
}

fn now_micros() -> i128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| elapsed.as_micros() as i128)
}

#[cfg(all(test, unix))]
#[path = "daemon_edge_auth_tests.rs"]
mod tests;
