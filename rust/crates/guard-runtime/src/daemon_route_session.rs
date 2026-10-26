//! Daemon origin policy and dashboard-session authorization.
//!
//! The transport verifies the session token's signature and expiry and hands
//! over the claims; everything that decides what those claims may reach lives
//! here. Single-use nonces are stateful, so a verdict that depends on one
//! names it in `consume_nonce` and the caller consumes it before honoring the
//! verdict.

use crate::daemon_route_paths::{
    hosted_dashboard_api_path, protection_repair_session_allowed, segments, session_path,
    supply_chain_claim_action,
};
use guard_contracts::{DaemonRoutePayloadV1, DaemonSessionClaimsV1, DaemonSessionPayloadV1};

const HOSTED_ORIGINS: &[&str] = &["https://hol.org", "https://www.hol.org"];
const LOCAL_SURFACES: &[&str] = &["approval-center", "dashboard", "cloud-dashboard"];
const PROTECTION_REPAIR_SURFACE: &str = "protection-repair";

/// Host of a transport-normalized origin (`scheme://host[:port]`), without
/// IPv6 brackets. `None` when the value is not that shape.
fn origin_host(origin: &str) -> Option<&str> {
    let rest = origin
        .strip_prefix("http://")
        .or_else(|| origin.strip_prefix("https://"))?;
    if let Some(inner) = rest.strip_prefix('[') {
        let (host, tail) = inner.split_once(']')?;
        return (tail.is_empty() || tail.starts_with(':')).then_some(host);
    }
    Some(rest.split(':').next().unwrap_or(rest))
}

pub(crate) fn origin_decision(origin: &str, path: &str) -> DaemonRoutePayloadV1 {
    let hosted_origin = HOSTED_ORIGINS.contains(&origin);
    let local = matches!(origin_host(origin), Some("127.0.0.1" | "localhost" | "::1"));
    DaemonRoutePayloadV1::Origin {
        allowed: local || (hosted_origin && hosted_dashboard_api_path(path)),
        hosted_origin,
    }
}

/// Accepts only a canonical `http://127.0.0.1:<port>` or `http://[::1]:<port>`
/// origin, written exactly that way (optionally with one trailing slash).
pub(crate) fn strict_loopback_origin(raw: &str, normalized: Option<&str>) -> Option<String> {
    let normalized = normalized?;
    let rest = normalized.strip_prefix("http://")?;
    let (host, port_text) = if let Some(inner) = rest.strip_prefix('[') {
        let (host, tail) = inner.split_once(']')?;
        (host, tail.strip_prefix(':')?)
    } else {
        rest.split_once(':')?
    };
    let canonical_host = match host {
        "::1" => "[::1]",
        "127.0.0.1" => "127.0.0.1",
        _ => return None,
    };
    if port_text.is_empty() || !port_text.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    let port: u32 = port_text.parse().ok()?;
    if !(1..=65535).contains(&port) {
        return None;
    }
    let canonical = format!("http://{canonical_host}:{port}");
    let slashed = format!("{canonical}/");
    (normalized == canonical && (raw == canonical || raw == slashed)).then_some(canonical)
}

fn cloud_app_session_actions(action_path: &str) -> Vec<&str> {
    match action_path {
        "connect" => vec!["connect", "status", "test"],
        "repair" => vec!["repair", "status", "test"],
        "status" => vec!["status"],
        "test" => vec!["status", "test"],
        other => vec![other],
    }
}

fn first<'a>(primary: &'a Option<String>, secondary: &'a Option<String>) -> Option<&'a str> {
    primary.as_deref().or(secondary.as_deref())
}

pub(crate) struct SessionRequest<'a> {
    pub method: &'a str,
    pub path: &'a str,
    pub claims: &'a DaemonSessionClaimsV1,
    pub payload: Option<&'a DaemonSessionPayloadV1>,
    pub header_nonce: Option<&'a str>,
    pub request_origin: Option<&'a str>,
}

pub(crate) fn session_authorize(request: &SessionRequest<'_>) -> DaemonRoutePayloadV1 {
    let (allowed, consume_nonce) = decide(request);
    DaemonRoutePayloadV1::SessionAuthorize {
        allowed,
        consume_nonce,
    }
}

fn decide(request: &SessionRequest<'_>) -> (bool, Option<String>) {
    let claims = request.claims;
    let surface = claims.surface.as_deref();
    if surface == Some(PROTECTION_REPAIR_SURFACE) {
        return (
            protection_repair_session_allowed(request.method, request.path),
            None,
        );
    }
    if surface.is_some_and(|name| LOCAL_SURFACES.contains(&name)) {
        return (session_path(request.method, request.path), None);
    }
    let Some(action_path) = claims.action_path.as_deref() else {
        return (false, None);
    };
    let parts = segments(request.path);
    if request.method == "GET" && read_path_allowed(claims, request.path) {
        return (scoped_nonce_matches(request), None);
    }
    if parts.len() == 3
        && parts[..2] == ["v1", "apps"]
        && cloud_app_session_actions(action_path).contains(&parts[2])
    {
        return (cloud_app_claims_match(claims, request.payload), None);
    }
    if let Some(action) = supply_chain_claim_action(request.path) {
        return supply_chain_authorize(request, action_path, &action);
    }
    (false, None)
}

fn read_path_allowed(claims: &DaemonSessionClaimsV1, path: &str) -> bool {
    claims
        .allowed_read_paths
        .as_ref()
        .is_some_and(|paths| paths.iter().any(|item| item == path))
}

fn scoped_nonce_matches(request: &SessionRequest<'_>) -> bool {
    let Some(claim_nonce) = request.claims.nonce.as_deref() else {
        return true;
    };
    let request_nonce = request.header_nonce.or_else(|| {
        request
            .payload
            .and_then(|payload| payload.dashboard_session_nonce.as_deref())
    });
    request_nonce == Some(claim_nonce)
}

fn cloud_app_claims_match(
    claims: &DaemonSessionClaimsV1,
    payload: Option<&DaemonSessionPayloadV1>,
) -> bool {
    let Some(payload) = payload else {
        return false;
    };
    let Some(harness) = claims.harness.as_deref() else {
        return false;
    };
    let claim_location = claims.location_id.as_deref().unwrap_or("");
    let claim_workspace = claims.workspace_id.as_deref().unwrap_or("");
    let payload_location = first(&payload.location_id, &payload.location_id_camel);
    let payload_workspace = payload.workspace_id.as_deref().unwrap_or("");
    payload.harness.as_deref() == Some(harness)
        && (claim_location.is_empty() || payload_location == Some(claim_location))
        && (claim_workspace.is_empty() || payload_workspace == claim_workspace)
}

fn supply_chain_authorize(
    request: &SessionRequest<'_>,
    action_path: &str,
    action: &str,
) -> (bool, Option<String>) {
    let claims = request.claims;
    let scoped = action == action_path
        || claims
            .allowed_action_paths
            .as_ref()
            .is_some_and(|paths| paths.iter().any(|item| item == action));
    if !scoped {
        return (false, None);
    }
    let consume = claims.nonce.clone();
    let Some(payload) = request.payload else {
        let bare = matches!(action, "package_shims_status" | "supply_chain_bundle");
        return (bare, consume);
    };
    (supply_chain_payload_matches(request, payload), consume)
}

fn supply_chain_payload_matches(
    request: &SessionRequest<'_>,
    payload: &DaemonSessionPayloadV1,
) -> bool {
    let claims = request.claims;
    let workspace = first(&claims.workspace_id, &claims.workspace_id_camel).unwrap_or("");
    let payload_workspace = first(&payload.workspace_id, &payload.workspace_id_camel).unwrap_or("");
    if !workspace.is_empty() && payload_workspace != workspace {
        return false;
    }
    let location = first(&claims.location_id, &claims.location_id_camel).unwrap_or("");
    let payload_location = first(&payload.location_id, &payload.location_id_camel).unwrap_or("");
    if !location.is_empty() && payload_location != location {
        return false;
    }
    if let Some(daemon_origin) = first(&claims.daemon_origin, &claims.daemon_origin_camel) {
        let payload_origin =
            first(&payload.daemon_origin, &payload.daemon_origin_camel).or(request.request_origin);
        if payload_origin != Some(daemon_origin) {
            return false;
        }
    }
    let Some(allowed) = claims.managers.as_ref() else {
        return true;
    };
    match &payload.managers {
        guard_contracts::DaemonListFieldV1::Absent => true,
        guard_contracts::DaemonListFieldV1::Invalid => false,
        guard_contracts::DaemonListFieldV1::Strings { values } => {
            values.iter().all(|manager| allowed.contains(manager))
        }
    }
}
