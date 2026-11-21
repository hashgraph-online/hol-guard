//! `DaemonRoute` — resident op for the daemon's route, origin and session policy.
//!
//! Pure: every query is answered from the request alone. A rejected query is a
//! bound `error` reply carrying its specific code, never a default verdict.

use crate::daemon_route_paths::{requires_header_token, route_class, session_path};
use crate::daemon_route_resolve::resolve_request;
use crate::daemon_route_session::{
    origin_decision, session_authorize, strict_loopback_origin, SessionRequest,
};
use crate::package_authority_op::request_digest_with_limit;
use guard_contracts::{
    DaemonRoutePayloadV1, DaemonRouteQueryV1, DaemonRouteRequestV1, DaemonRouteResultV1,
    DAEMON_ROUTE_MAX_BYTES, DAEMON_ROUTE_REQUEST_SCHEMA, DAEMON_ROUTE_RESULT_SCHEMA,
};

pub(crate) fn evaluate_daemon_route_request(
    request: &DaemonRouteRequestV1,
) -> Result<Vec<u8>, String> {
    // Bound the complete canonical request before any decision work; an
    // oversized request has no digest to bind.
    let request_sha256 = request_digest_with_limit(request, DAEMON_ROUTE_MAX_BYTES)
        .map_err(|_| "native_daemon_route_too_large".to_owned())?;
    let (status, code, payload) = match decide(request) {
        Ok(payload) => ("ok", "ok".to_owned(), Some(payload)),
        Err(code) => ("error", code, None),
    };
    crate::encode_response(&DaemonRouteResultV1 {
        schema: DAEMON_ROUTE_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code,
        payload,
    })
}

pub(crate) fn decide(request: &DaemonRouteRequestV1) -> Result<DaemonRoutePayloadV1, String> {
    if request.schema != DAEMON_ROUTE_REQUEST_SCHEMA {
        return Err("native_daemon_route_schema_mismatch".to_owned());
    }
    Ok(match &request.query {
        DaemonRouteQueryV1::Route { method, path } => DaemonRoutePayloadV1::Route {
            requires_header_token: requires_header_token(path),
            session_path: session_path(method, path),
            route_class: route_class(path).to_owned(),
        },
        DaemonRouteQueryV1::Origin { origin, path } => origin_decision(origin, path),
        DaemonRouteQueryV1::StrictLoopback { raw, normalized } => {
            DaemonRoutePayloadV1::StrictLoopback {
                origin: strict_loopback_origin(raw, normalized.as_deref()),
            }
        }
        DaemonRouteQueryV1::SessionAuthorize {
            method,
            path,
            claims,
            payload,
            header_nonce,
            request_origin,
        } => session_authorize(&SessionRequest {
            method,
            path,
            claims,
            payload: payload.as_ref(),
            header_nonce: header_nonce.as_deref(),
            request_origin: request_origin.as_deref(),
        }),
        DaemonRouteQueryV1::ResolveRequest {
            path,
            action,
            scope,
            scope_contract_version,
            scope_contract_digest,
        } => resolve_request(
            path,
            action,
            scope,
            scope_contract_version,
            scope_contract_digest,
        ),
    })
}

#[cfg(test)]
#[path = "daemon_route_op_tests.rs"]
mod tests;
