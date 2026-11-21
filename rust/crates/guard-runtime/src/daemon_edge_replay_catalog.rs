//! `GET /v2/extension-controls/catalog/*` (ADR 0014), for a caller the edge
//! has already authenticated: the native catalog read model's bytes, written
//! verbatim with their `ETag`, or `501` so a client can fall back to the v1
//! catalog. Any other `/v2/` path is `404 not_found`.
//!
//! Rollback: `HOL_GUARD_CATALOG_READ_V2=off` answers every catalog read with
//! that `501`.

use serde_json::{json, Value};

use super::super::auth::authorize_origin;
use super::super::http::Request;
use super::super::library;
use super::super::reads::{json_response, ReadConfig};

const PREFIX: &str = "/v2/extension-controls/catalog/";
const UNAVAILABLE: &str = "catalog_read_model_unavailable";
const ROLLOUT_ENV: &str = "HOL_GUARD_CATALOG_READ_V2";

/// The whole response to an authenticated `GET` under `/v2/`.
pub(super) fn respond(request: &Request<'_>, config: &ReadConfig) -> Vec<u8> {
    let build = config.dashboard_build();
    let Some(route) = request.path.strip_prefix(PREFIX) else {
        return json_response(404, &json!({"error": "not_found"}), build, None, false);
    };
    if !enabled(std::env::var(ROLLOUT_ENV).ok().as_deref()) {
        return error(501, UNAVAILABLE, build);
    }
    let reply = library::call_resident(
        config,
        "route.catalog_v2",
        json!({
            "route": route,
            "query": request.query,
            "if_none_match": request.single_header("If-None-Match"),
        }),
    );
    let Ok(reply) = reply else {
        return error(501, UNAVAILABLE, build);
    };
    let status = reply
        .get("status")
        .and_then(Value::as_u64)
        .and_then(|status| u16::try_from(status).ok());
    let etag = reply.get("etag").and_then(Value::as_str);
    match (status, reply.get("error").and_then(Value::as_str)) {
        (Some(status), Some(code)) => error(status, code, build),
        (Some(304), None) if etag.is_some() => {
            let origin = authorize_origin(request).and_then(|caller| caller.cors_origin);
            representation(304, etag, origin.as_deref(), None, build)
        }
        (Some(200), None) => match (etag, reply.get("body").and_then(Value::as_str)) {
            (Some(etag), Some(body)) => {
                let origin = authorize_origin(request).and_then(|caller| caller.cors_origin);
                representation(200, Some(etag), origin.as_deref(), Some(body), build)
            }
            _ => error(501, UNAVAILABLE, build),
        },
        _ => error(501, UNAVAILABLE, build),
    }
}

/// `catalog_read_v2_enabled`.
fn enabled(value: Option<&str>) -> bool {
    !matches!(
        value
            .map(|value| value.trim().to_ascii_lowercase())
            .as_deref(),
        Some("0" | "off" | "false" | "disabled")
    )
}

/// `write_catalog_v2_error`.
fn error(status: u16, code: &str, build: Option<&str>) -> Vec<u8> {
    json_response(status, &json!({ "error": code }), build, None, true)
}

/// `write_catalog_v2_body` and `write_catalog_v2_empty`.
fn representation(
    status: u16,
    etag: Option<&str>,
    cors_origin: Option<&str>,
    body: Option<&str>,
    build: Option<&str>,
) -> Vec<u8> {
    let reason = if status == 304 { "Not Modified" } else { "OK" };
    let mut head = format!("HTTP/1.0 {status} {reason}\r\n");
    if let Some(body) = body {
        head.push_str(&format!(
            "Content-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nX-Content-Type-Options: nosniff\r\n",
            body.len()
        ));
    } else {
        head.push_str("Content-Length: 0\r\n");
    }
    if let Some(origin) = cors_origin {
        head.push_str(&format!(
            "Access-Control-Allow-Origin: {origin}\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Private-Network: true\r\nVary: Origin\r\n"
        ));
    }
    head.push_str(&format!(
        "Cache-Control: private, no-cache\r\nETag: {}\r\nAccess-Control-Expose-Headers: ETag\r\n",
        etag.unwrap_or_default()
    ));
    if let Some(build) = build {
        head.push_str(&format!("X-Guard-Dashboard-Build: {build}\r\n"));
    }
    head.push_str("Connection: close\r\n\r\n");
    let mut response = head.into_bytes();
    response.extend_from_slice(body.unwrap_or_default().as_bytes());
    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_rollback_switch_turns_reads_off() {
        assert!(enabled(None));
        assert!(enabled(Some("on")));
        for value in ["0", "off", " OFF ", "false", "disabled"] {
            assert!(!enabled(Some(value)), "{value}");
        }
    }

    #[test]
    fn a_representation_carries_its_validator() {
        let body = String::from_utf8(representation(
            200,
            Some("\"cr1-0\""),
            Some("http://127.0.0.1:1"),
            Some("{}"),
            None,
        ))
        .unwrap();
        assert!(body.starts_with("HTTP/1.0 200 OK\r\n"));
        assert!(body.contains("ETag: \"cr1-0\"\r\n"));
        assert!(body.contains("Access-Control-Allow-Origin: http://127.0.0.1:1\r\n"));
        assert!(body.ends_with("\r\n\r\n{}"));
        let empty =
            String::from_utf8(representation(304, Some("\"e\""), None, None, None)).unwrap();
        assert!(empty.starts_with("HTTP/1.0 304 Not Modified\r\n"));
        assert!(empty.contains("Content-Length: 0\r\n"));
    }
}
