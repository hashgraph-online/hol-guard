//! Requests no native route answers: the daemon parses them, answers a
//! preflight, an unsupported method or a malformed request itself, and runs
//! the rest through the route handler in the Guard library (the
//! `route.request` call), which applies every origin, auth and body check it
//! always has and returns the raw response, written back unchanged.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::time::{Duration, Instant};

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use serde_json::{json, Value};

use super::auth::{authorize_origin, normalize_origin};
use super::http::{parse_request, Request};
use super::library;
use super::reads::ReadConfig;

/// How long the client has to send the rest of its request.
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// The handler refuses bodies past 1,000,000 bytes; past this the edge sends
/// the head alone and lets it say so.
const MAX_REPLAYED_BODY_BYTES: usize = 1_000_000;
const MAX_REPLAYED_HEAD_BYTES: usize = 64 * 1024;

const UNAVAILABLE: &[u8] = b"HTTP/1.0 503 Service Unavailable\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: 38\r\nConnection: close\r\n\r\n{\"error\": \"daemon_route_unavailable\"}\n";

/// Answers the request on `client` through the route handler. `read_ahead` is the
/// request the edge already took off the socket, or empty when it took
/// nothing.
pub(in crate::daemon_edge) fn replay(
    client: &TcpStream,
    config: &ReadConfig,
    read_ahead: Vec<u8>,
    stalled_write: Duration,
    daemon_pid: u32,
) {
    let request = if read_ahead.is_empty() {
        read_request(client, REQUEST_READ_TIMEOUT)
    } else {
        Some(read_ahead)
    };
    let Some(request) = request else {
        let _ = client.shutdown(Shutdown::Both);
        return;
    };
    replay_with(client, config, request, stalled_write, daemon_pid, false);
}

/// Answers `request`, already read off `client`, through the route handler.
/// `proof_verified` tells the handler the edge checked the daemon identity
/// proof this hook presents on its connection.
pub(in crate::daemon_edge) fn replay_with(
    client: &TcpStream,
    config: &ReadConfig,
    request: Vec<u8>,
    stalled_write: Duration,
    daemon_pid: u32,
    proof_verified: bool,
) {
    let response = client.local_addr().ok().and_then(|local| {
        own_answer(&request, config.dashboard_build()).or_else(|| {
            run(config, local.port(), daemon_pid, proof_verified, &request)
                .filter(|response| !response.is_empty())
        })
    });
    let _ = client.set_write_timeout(Some(stalled_write));
    let mut writer = client;
    let _ = writer.write_all(response.as_deref().unwrap_or(UNAVAILABLE));
    let _ = client.shutdown(Shutdown::Both);
}

/// `do_OPTIONS`, the `501` an unsupported method gets and the `400` a
/// request line that does not parse gets; `None` for a request the route
/// handler answers.
fn own_answer(request: &[u8], build: Option<&str>) -> Option<Vec<u8>> {
    let head = &request[..find_head_end(request)?];
    let method = head.split(|byte| *byte == b' ').next().unwrap_or_default();
    match method {
        b"GET" | b"POST" | b"DELETE" => parse_request(head)
            .is_none()
            .then(|| empty_response(400, build, &[])),
        // The edge reads a preflight's head as it reads a `GET`'s.
        b"OPTIONS" => Some(
            match parse_request(&[b"GET", &head[method.len()..]].concat()) {
                Some(head) => preflight(&head, build),
                None => empty_response(400, build, &[]),
            },
        ),
        method if !method.is_empty() && method.iter().all(u8::is_ascii_uppercase) => {
            Some(super::reads::json_response(
                501,
                &json!({ "error": "unsupported_method" }),
                build,
                None,
                false,
            ))
        }
        _ => Some(empty_response(400, build, &[])),
    }
}

/// The headers `do_OPTIONS` allows a dashboard's preflight.
const PREFLIGHT_ALLOW_HEADERS: &str = "Authorization, Content-Type, If-None-Match, Last-Event-ID, X-Guard-Dashboard-Session, X-Guard-Token";

/// `do_OPTIONS`: `400` without a readable `Origin`, `403` for one the path
/// does not allow, and the CORS headers otherwise.
fn preflight(request: &Request<'_>, build: Option<&str>) -> Vec<u8> {
    let Some(origin) = request.single_header("Origin").and_then(normalize_origin) else {
        return empty_response(400, build, &[]);
    };
    if authorize_origin(request).is_none() {
        return empty_response(403, build, &[]);
    }
    empty_response(
        200,
        build,
        &[
            ("Access-Control-Allow-Origin", origin.as_str()),
            ("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS"),
            ("Access-Control-Allow-Headers", PREFLIGHT_ALLOW_HEADERS),
            ("Access-Control-Allow-Private-Network", "true"),
            ("Vary", "Origin"),
        ],
    )
}

/// `_write_empty`: a status, the given headers and no body.
fn empty_response(status: u16, build: Option<&str>, headers: &[(&str, &str)]) -> Vec<u8> {
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        _ => "Forbidden",
    };
    let mut response = format!("HTTP/1.0 {status} {reason}\r\n");
    for (name, value) in headers {
        response.push_str(&format!("{name}: {value}\r\n"));
    }
    if let Some(build) = build {
        response.push_str(&format!("X-Guard-Dashboard-Build: {build}\r\n"));
    }
    response.push_str("Content-Length: 0\r\nConnection: close\r\n\r\n");
    response.into_bytes()
}

/// One request's head and declared body, read straight off the socket
/// within `timeout`.
pub(in crate::daemon_edge) fn read_request(
    client: &TcpStream,
    timeout: Duration,
) -> Option<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 8192];
    let head_len = loop {
        if let Some(end) = find_head_end(&bytes) {
            break end;
        }
        if bytes.len() >= MAX_REPLAYED_HEAD_BYTES {
            return None;
        }
        let read = read_some(client, &mut chunk, deadline)?;
        bytes.extend_from_slice(&chunk[..read]);
    };
    let declared = content_length(&bytes[..head_len]);
    let Some(length) = declared.filter(|length| *length <= MAX_REPLAYED_BODY_BYTES) else {
        // No body, or one the handler refuses by its declared length alone.
        bytes.truncate(head_len);
        return Some(bytes);
    };
    let total = head_len + length;
    while bytes.len() < total {
        let read = read_some(client, &mut chunk, deadline)?;
        bytes.extend_from_slice(&chunk[..read]);
    }
    bytes.truncate(total);
    Some(bytes)
}

fn read_some(client: &TcpStream, chunk: &mut [u8], deadline: Instant) -> Option<usize> {
    loop {
        let remaining = deadline.checked_duration_since(Instant::now())?;
        if remaining.is_zero() || client.set_read_timeout(Some(remaining)).is_err() {
            return None;
        }
        let mut reader = client;
        match reader.read(chunk) {
            Ok(0) => return None,
            Ok(read) => return Some(read),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }
}

pub(in crate::daemon_edge) fn find_head_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

/// The one `Content-Length` the head declares; `None` for none, several, or
/// one that is not a number.
pub(in crate::daemon_edge) fn content_length(head: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(head).ok()?;
    let mut values = text.split("\r\n").skip(1).filter_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-length")
            .then(|| value.trim())
    });
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.parse().ok()
}

/// The route handler's raw response to `request`, or `None` when the call
/// could not run or answered nothing usable.
fn run(
    config: &ReadConfig,
    port: u16,
    daemon_pid: u32,
    proof_verified: bool,
    request: &[u8],
) -> Option<Vec<u8>> {
    let answer = library::call(
        config,
        "route.request",
        request_args(request, port, daemon_pid, proof_verified),
    )
    .ok()?;
    STANDARD.decode(answer.get("response")?.as_str()?).ok()
}

/// The `route.request` arguments for one request. `daemon_pid` is the
/// process the published daemon state names.
fn request_args(request: &[u8], port: u16, daemon_pid: u32, proof_verified: bool) -> Value {
    json!({
        "request": STANDARD.encode(request),
        "port": port,
        "daemon_pid": daemon_pid,
        "proof_verified": proof_verified,
    })
}

#[cfg(all(test, unix))]
#[path = "daemon_edge_replay_tests.rs"]
mod tests;
