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
use guard_contracts::{DaemonRoutePayloadV1, DaemonSessionClaimsV1};
use hmac::{Hmac, Mac};
use serde_json::{Map, Value};
use sha2::Sha256;

use super::http::Request;
use crate::daemon_route_paths::session_path;
use crate::daemon_route_session::{origin_decision, session_authorize, SessionRequest};
use crate::guard_store_json::{aware_epoch_micros, py_strip};
use crate::resident_transport::constant_time_eq;

const SESSION_PREFIX: &str = "gld1";
const SESSION_AUDIENCE: &str = "guard-local-daemon";
/// A session this close to its expiry goes to the daemon, so the edge never
/// honors one the daemon's own clock has already ended.
const EXPIRY_MARGIN_MICROS: i128 = 1_000_000;

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

/// A caller the daemon would let write: an allowed origin and its auth token.
/// A dashboard session goes to the daemon, whose write verdicts can spend a
/// nonce.
pub(super) fn authorize_token(request: &Request<'_>, token: &[u8]) -> Option<Caller> {
    let caller = allowed_origin(request)?;
    token_matches(request, token)?.then_some(caller)
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
fn session_allows(request: &Request<'_>, token: &[u8], origin: Option<&str>) -> bool {
    if !session_path("GET", request.path) {
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
            method: "GET",
            path: request.path,
            claims: &claims,
            payload: None,
            header_nonce,
            request_origin: origin,
        });
        matches!(
            verdict,
            DaemonRoutePayloadV1::SessionAuthorize {
                allowed: true,
                consume_nonce: None,
            }
        )
    })
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
fn verified_claims(session: &str, token: &[u8], now: i128) -> Option<DaemonSessionClaimsV1> {
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
    if expires_at <= now + EXPIRY_MARGIN_MICROS {
        return None;
    }
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

#[cfg(test)]
#[path = "daemon_edge_auth_tests.rs"]
mod tests;
