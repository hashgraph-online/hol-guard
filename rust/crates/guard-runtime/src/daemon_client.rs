//! The local daemon client (`daemon-client --stdin`): one authenticated,
//! loopback-only HTTP exchange with the running Guard daemon.
//!
//! The CLI reaches the daemon through this command instead of its own HTTP
//! stack. Every exchange is direct (no proxy, no redirect), bounded by one
//! monotonic deadline and a response size cap, and answered with either the
//! decoded JSON object or a classified failure the caller maps onto its
//! exceptions: `timeout`, `transport`, `schema` or `http` (with the daemon's
//! error code and recovery action).

use std::io::{Read, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{json, Map, Value};

#[path = "daemon_client_catalog.rs"]
mod catalog;

use crate::native_review_link::{now_micros, session_token};

const SCHEMA: &str = "daemon-client.v1";
const MAX_REQUEST_BYTES: u64 = 16 * 1024 * 1024;
/// The largest body any caller may ask for (the extension catalog).
const MAX_RESPONSE_BYTES: usize = 8 * 1024 * 1024;
const DEFAULT_RESPONSE_BYTES: usize = 1024 * 1024;
const ERROR_BODY_BYTES: usize = 1024 * 1024;
const HEALTH_BYTES: usize = 64 * 1024;
const HEADER_BYTES: usize = 64 * 1024;
const RETRY_FLOOR: Duration = Duration::from_millis(50);
const DASHBOARD_PROTOCOL_VERSIONS: [&str; 2] = ["1.1", "1.0"];

pub(crate) fn is_command(command: &str) -> bool {
    command == "daemon-client"
}

#[derive(Clone, Deserialize)]
struct Request {
    schema: String,
    op: String,
    daemon_url: String,
    #[serde(default)]
    auth: String,
    #[serde(default)]
    method: String,
    #[serde(default)]
    path: String,
    #[serde(default)]
    body: Option<Value>,
    timeout_ms: u64,
    #[serde(default)]
    max_bytes: Option<usize>,
    #[serde(default)]
    if_none_match: Option<String>,
    #[serde(default)]
    route: String,
    #[serde(default)]
    item_key: String,
    #[serde(default)]
    params: Option<Value>,
    #[serde(default)]
    extension_id: String,
}

#[derive(Debug, PartialEq)]
enum Fail {
    Timeout,
    Transport(&'static str),
    Truncated(Vec<u8>),
    TooLarge,
}

struct Reply {
    status: u16,
    etag: Option<String>,
    body: Vec<u8>,
}

pub(crate) fn run_command(reader: impl Read) -> Result<Vec<u8>, String> {
    let mut bytes = Vec::new();
    reader
        .take(MAX_REQUEST_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "daemon_client_request_unreadable".to_owned())?;
    if bytes.len() as u64 > MAX_REQUEST_BYTES {
        return Err("daemon_client_request_too_large".to_owned());
    }
    let request: Request =
        serde_json::from_slice(&bytes).map_err(|_| "daemon_client_request_invalid".to_owned())?;
    if request.schema != SCHEMA {
        return Err("daemon_client_unsupported_schema".to_owned());
    }
    let answer = answer(&request);
    let mut out = serde_json::to_vec(&answer).map_err(|error| error.to_string())?;
    out.push(b'\n');
    Ok(out)
}

fn answer(request: &Request) -> Value {
    let deadline = Instant::now() + Duration::from_millis(request.timeout_ms);
    let Some(addr) = loopback_authority(&request.daemon_url) else {
        return failure("transport", "Guard daemon address is not loopback", None);
    };
    if request.timeout_ms == 0 {
        return failure("timeout", "Guard daemon request timed out", None);
    }
    match request.op.as_str() {
        "health_details" => match health_details(addr, &request.auth, deadline) {
            Some(map) => json!({"ok": map}),
            None => json!({"none": true}),
        },
        "dashboard_capabilities" => dashboard_capabilities(addr, &request.auth, deadline),
        "catalog_get" | "catalog_traverse" | "catalog_extension" => {
            catalog::answer(request, addr, deadline)
        }
        "request" => {
            let limit = request
                .max_bytes
                .unwrap_or(DEFAULT_RESPONSE_BYTES)
                .clamp(1, MAX_RESPONSE_BYTES);
            json_request(request, addr, deadline, limit)
        }
        _ => failure("schema", "unsupported daemon client op", None),
    }
}

fn failure(kind: &str, message: &str, status: Option<u16>) -> Value {
    json!({"error": kind, "message": message, "status": status})
}

/// `http://127.0.0.1:<port>` or `http://[::1]:<port>` with no path, user,
/// query or fragment.
fn loopback_authority(url: &str) -> Option<SocketAddr> {
    let rest = url.strip_prefix("http://")?;
    let authority = rest.strip_suffix('/').unwrap_or(rest);
    if authority.contains(['/', '@', '?', '#']) {
        return None;
    }
    let (host, port) = authority.rsplit_once(':')?;
    let port: u16 = port.parse().ok().filter(|port| *port != 0)?;
    let ip = match host {
        "127.0.0.1" => std::net::IpAddr::from([127, 0, 0, 1]),
        "[::1]" => std::net::IpAddr::from(std::net::Ipv6Addr::LOCALHOST),
        _ => return None,
    };
    Some(SocketAddr::new(ip, port))
}

fn remaining(deadline: Instant) -> Result<Duration, Fail> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        Err(Fail::Timeout)
    } else {
        Ok(left)
    }
}

fn io_fail(error: &std::io::Error) -> Fail {
    match error.kind() {
        std::io::ErrorKind::TimedOut | std::io::ErrorKind::WouldBlock => Fail::Timeout,
        _ => Fail::Transport("Guard daemon request failed"),
    }
}

/// One HTTP/1.1 exchange under `deadline`, reading at most `limit` body bytes.
fn exchange(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    deadline: Instant,
    limit: usize,
) -> Result<Reply, Fail> {
    let mut stream =
        TcpStream::connect_timeout(&addr, remaining(deadline)?).map_err(|error| io_fail(&error))?;
    let host = match addr {
        SocketAddr::V4(v4) => format!("{}:{}", v4.ip(), v4.port()),
        SocketAddr::V6(v6) => format!("[{}]:{}", v6.ip(), v6.port()),
    };
    let mut head = format!("{method} {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\n");
    for (name, value) in headers {
        if name.contains(['\r', '\n']) || value.contains(['\r', '\n']) {
            return Err(Fail::Transport("Guard daemon request header is invalid"));
        }
        head.push_str(&format!("{name}: {value}\r\n"));
    }
    if let Some(body) = body {
        head.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    head.push_str("\r\n");
    let mut wire = head.into_bytes();
    wire.extend_from_slice(body.unwrap_or_default());
    stream
        .set_write_timeout(Some(remaining(deadline)?))
        .map_err(|error| io_fail(&error))?;
    stream.write_all(&wire).map_err(|error| io_fail(&error))?;
    let raw = read_bounded(&mut stream, deadline, HEADER_BYTES + limit + 64)?;
    let _ = stream.shutdown(Shutdown::Both);
    parse_response(&raw, limit)
}

fn read_bounded(stream: &mut TcpStream, deadline: Instant, cap: usize) -> Result<Vec<u8>, Fail> {
    let mut raw = Vec::new();
    let mut chunk = [0_u8; 65_536];
    loop {
        stream
            .set_read_timeout(Some(remaining(deadline)?))
            .map_err(|error| io_fail(&error))?;
        let read = stream.read(&mut chunk).map_err(|error| io_fail(&error))?;
        if read == 0 {
            return Ok(raw);
        }
        raw.extend_from_slice(&chunk[..read]);
        if raw.len() > cap {
            return Err(Fail::TooLarge);
        }
        if complete(&raw) {
            return Ok(raw);
        }
    }
}

/// A response with a `Content-Length` is complete once that many body bytes
/// arrived, so a daemon holding the socket open cannot run out the deadline.
fn complete(raw: &[u8]) -> bool {
    let Some(end) = raw.windows(4).position(|window| window == b"\r\n\r\n") else {
        return false;
    };
    let Ok(text) = std::str::from_utf8(&raw[..end]) else {
        return false;
    };
    header_value(text, "content-length")
        .and_then(|value| value.parse::<usize>().ok())
        .is_some_and(|length| raw.len() >= end + 4 + length)
}

fn header_value<'a>(head: &'a str, name: &str) -> Option<&'a str> {
    head.split("\r\n").skip(1).find_map(|line| {
        let (key, value) = line.split_once(':')?;
        key.trim().eq_ignore_ascii_case(name).then(|| value.trim())
    })
}

fn parse_response(raw: &[u8], limit: usize) -> Result<Reply, Fail> {
    let Some(end) = raw.windows(4).position(|window| window == b"\r\n\r\n") else {
        return Err(Fail::Transport("Guard daemon response was truncated"));
    };
    let head = std::str::from_utf8(&raw[..end])
        .map_err(|_| Fail::Transport("Guard daemon response is malformed"))?;
    let mut status_line = head.split("\r\n").next().unwrap_or("").split_whitespace();
    if !status_line.next().is_some_and(|v| v.starts_with("HTTP/1.")) {
        return Err(Fail::Transport("Guard daemon response is malformed"));
    }
    let status: u16 = status_line
        .next()
        .and_then(|code| code.parse().ok())
        .ok_or(Fail::Transport("Guard daemon response is malformed"))?;
    let body = &raw[end + 4..];
    let chunked = header_value(head, "transfer-encoding")
        .is_some_and(|value| value.eq_ignore_ascii_case("chunked"));
    let body = if chunked {
        dechunk(body)?
    } else if let Some(length) = header_value(head, "content-length") {
        let length: usize = length
            .parse()
            .map_err(|_| Fail::Transport("Guard daemon response is malformed"))?;
        if length > limit {
            return Err(Fail::TooLarge);
        }
        if body.len() < length {
            return Err(Fail::Truncated(body.to_vec()));
        }
        body[..length].to_vec()
    } else {
        body.to_vec()
    };
    if body.len() > limit {
        return Err(Fail::TooLarge);
    }
    let etag = header_value(head, "etag").map(str::to_owned);
    Ok(Reply { status, etag, body })
}

fn dechunk(mut raw: &[u8]) -> Result<Vec<u8>, Fail> {
    let mut body = Vec::new();
    loop {
        let Some(line_end) = raw.windows(2).position(|window| window == b"\r\n") else {
            return Err(Fail::Truncated(body));
        };
        let size_text = std::str::from_utf8(&raw[..line_end])
            .map_err(|_| Fail::Transport("Guard daemon response is malformed"))?;
        let size_text = size_text.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size_text, 16)
            .map_err(|_| Fail::Transport("Guard daemon response is malformed"))?;
        raw = &raw[line_end + 2..];
        if size == 0 {
            return Ok(body);
        }
        if raw.len() < size + 2 {
            body.extend_from_slice(&raw[..raw.len().min(size)]);
            return Err(Fail::Truncated(body));
        }
        body.extend_from_slice(&raw[..size]);
        raw = &raw[size + 2..];
    }
}

fn object(body: &[u8]) -> Option<Map<String, Value>> {
    match serde_json::from_slice(body).ok()? {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

fn token_header() -> String {
    format!("X-Guard-{}", "Token")
}

fn json_request(request: &Request, addr: SocketAddr, deadline: Instant, limit: usize) -> Value {
    let header = token_header();
    let payload = request.body.as_ref().map(serde_json::to_vec).transpose();
    let Ok(payload) = payload else {
        return failure("schema", "Guard daemon request body is invalid", None);
    };
    let mut headers = vec![(header.as_str(), request.auth.as_str())];
    if payload.is_some() {
        headers.push(("Content-Type", "application/json"));
    }
    if let Some(tag) = request.if_none_match.as_deref() {
        headers.push(("If-None-Match", tag));
    }
    let method = if request.method.is_empty() {
        "GET"
    } else {
        request.method.as_str()
    };
    let attempt = |limit| {
        exchange(
            addr,
            method,
            &request.path,
            &headers,
            payload.as_deref(),
            deadline,
            limit,
        )
    };
    let mut outcome = attempt(limit.max(ERROR_BODY_BYTES));
    if method == "GET" && matches!(outcome, Err(Fail::Truncated(_))) {
        if deadline.saturating_duration_since(Instant::now()) <= RETRY_FLOOR {
            return failure("transport", "Guard daemon response was truncated", None);
        }
        outcome = attempt(limit.max(ERROR_BODY_BYTES));
    }
    let reply = match outcome {
        Ok(reply) => reply,
        Err(Fail::Timeout) => return failure("timeout", "Guard daemon request timed out", None),
        Err(Fail::TooLarge) => {
            return failure(
                "schema",
                "Guard daemon response exceeded the size limit",
                None,
            )
        }
        Err(Fail::Truncated(partial)) => {
            if method != "GET" {
                if let Some(map) = object(&partial) {
                    return json!({"ok": map});
                }
            }
            return failure("transport", "Guard daemon response was truncated", None);
        }
        Err(Fail::Transport(message)) => return failure("transport", message, None),
    };
    if reply.status == 304 && request.if_none_match.is_some() {
        return json!({"not_modified": true, "etag": reply.etag});
    }
    if !(200..300).contains(&reply.status) {
        return http_failure(&reply);
    }
    if reply.body.len() > limit {
        return failure(
            "schema",
            "Guard daemon response exceeded the size limit",
            None,
        );
    }
    match object(&reply.body) {
        Some(map) => json!({"ok": map, "etag": reply.etag, "size": reply.body.len()}),
        None => failure("schema", "Guard daemon response schema is invalid", None),
    }
}

fn http_failure(reply: &Reply) -> Value {
    let payload = (reply.body.len() <= ERROR_BODY_BYTES)
        .then(|| object(&reply.body))
        .flatten()
        .unwrap_or_default();
    let code = payload.get("error").and_then(Value::as_str);
    let action = payload
        .get("recovery")
        .and_then(Value::as_object)
        .and_then(|recovery| recovery.get("action"))
        .and_then(Value::as_str);
    let message = format!(
        "Guard daemon request failed: {}",
        code.map_or_else(|| format!("HTTP Error {}", reply.status), str::to_owned)
    );
    json!({
        "error": "http",
        "message": message,
        "status": reply.status,
        "code": code,
        "recovery_action": action,
    })
}

/// `GET /v1/healthz/details`: 200 and a JSON object of at most 64 KiB, or
/// nothing.
fn health_details(addr: SocketAddr, auth: &str, deadline: Instant) -> Option<Map<String, Value>> {
    let header = token_header();
    let reply = exchange(
        addr,
        "GET",
        "/v1/healthz/details",
        &[(header.as_str(), auth)],
        None,
        deadline,
        HEALTH_BYTES,
    )
    .ok()?;
    if reply.status != 200 || Instant::now() >= deadline {
        return None;
    }
    object(&reply.body)
}

/// The browser's local handoff: seed a dashboard session, initialize the
/// surface, then read capabilities with only the refreshed session. Both
/// requests share one deadline.
fn dashboard_capabilities(addr: SocketAddr, auth: &str, deadline: Instant) -> Value {
    let header = "X-Guard-Dashboard-Session";
    let field = format!("dashboard_session_{}", "token");
    let Some(seed) = now_micros().and_then(|now| session_token(auth, "dashboard", now)) else {
        return failure("transport", "Guard daemon dashboard request failed", None);
    };
    let body = json!({
        "client_name": "guard-dashboard-web",
        "surface": "dashboard",
        "supported_protocol_versions": DASHBOARD_PROTOCOL_VERSIONS,
    });
    let Ok(body) = serde_json::to_vec(&body) else {
        return failure("transport", "Guard daemon dashboard request failed", None);
    };
    let initialized = dashboard_step(
        addr,
        "POST",
        "/v1/initialize",
        &[
            ("Content-Type", "application/json"),
            (header, seed.as_str()),
        ],
        Some(&body),
        deadline,
    );
    let initialized = match initialized {
        Ok(map) => map,
        Err(value) => return value,
    };
    let Some(refreshed) = initialized
        .get(&field)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
    else {
        return failure(
            "schema",
            "Guard daemon dashboard session response is invalid",
            None,
        );
    };
    match dashboard_step(
        addr,
        "GET",
        "/v1/capabilities",
        &[(header, refreshed)],
        None,
        deadline,
    ) {
        Ok(map) => json!({"ok": map}),
        Err(value) => value,
    }
}

fn dashboard_step(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    deadline: Instant,
) -> Result<Map<String, Value>, Value> {
    let reply = match exchange(
        addr,
        method,
        path,
        headers,
        body,
        deadline,
        DEFAULT_RESPONSE_BYTES,
    ) {
        Ok(reply) => reply,
        Err(Fail::Timeout) => {
            return Err(failure(
                "timeout",
                "Guard daemon dashboard session timed out",
                None,
            ))
        }
        Err(Fail::Truncated(_)) => {
            return Err(failure(
                "transport",
                "Guard daemon dashboard response was truncated",
                None,
            ))
        }
        Err(Fail::TooLarge) => {
            return Err(failure(
                "schema",
                "Guard daemon response exceeded the size limit",
                None,
            ))
        }
        Err(Fail::Transport(_)) => {
            return Err(failure(
                "transport",
                "Guard daemon dashboard request failed",
                None,
            ))
        }
    };
    if !(200..300).contains(&reply.status) {
        return Err(http_failure(&reply));
    }
    object(&reply.body).ok_or_else(|| {
        failure(
            "schema",
            "Guard daemon dashboard response schema is invalid",
            None,
        )
    })
}

#[cfg(test)]
#[path = "daemon_client_tests.rs"]
mod tests;
