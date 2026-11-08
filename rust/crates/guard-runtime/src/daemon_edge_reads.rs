//! Read routes the daemon edge answers without the Python daemon.
//!
//! Once the daemon starts the edge it writes one handshake line on the
//! liveness socket: the auth token and the store the daemon serves. Nothing
//! goes on disk, in the argument list or in the environment. Until that line
//! arrives, and for an older daemon that never sends it, the edge relays every
//! connection exactly as before.
//!
//! With a handshake the edge peeks at the head of each new connection, without
//! consuming it, for a few milliseconds. A head that has not fully arrived by
//! then, or that is followed by more bytes, leaves the connection untouched for
//! the daemon. The edge answers a request itself only when it is a `GET` for
//! one of the store reads below, with no body, from a caller `auth` finds the
//! daemon would let through: its token, or a dashboard session, from an
//! allowed origin. Anything else is replayed byte for byte to the daemon,
//! which keeps every rejection, audit record and nonce check it has today. A
//! store read that fails is replayed too, so the daemon answers it as it
//! always has. Only reads that never write the store are answered here.
//!
//! Each authenticated request writes one byte back on the liveness socket when
//! it starts and when it is answered, at most twice a second, so the daemon
//! still counts the activity it no longer sees.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::os::unix::net::UnixStream;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use guard_contracts::DaemonRoutePayloadV1;
use guard_contracts::{GuardStoreRequestV1, GUARD_STORE_REQUEST_SCHEMA};
use serde::Deserialize;
use serde_json::{json, Value};

use super::auth::authorize;
use super::http::{head_end, parse_get, query_int, query_value, GetRequest};
use crate::daemon_route_session::origin_decision;

pub(super) const HANDSHAKE_SCHEMA: &str = "guard-daemon-edge-handshake.v1";
pub(super) const MAX_HANDSHAKE_BYTES: usize = 64 * 1024;
const MAX_HEAD_BYTES: usize = 16 * 1024;
// A client that has not sent its whole head this soon after the edge accepted
// it goes to the daemon untouched, so the daemon's own partial-header
// admission and deadlines see it as before.
const HEAD_PEEK_WINDOW: Duration = Duration::from_millis(25);
const HEAD_PEEK_PAUSE: Duration = Duration::from_millis(1);
/// The request headers the daemon names in its CORS answer.
const CORS_ALLOW_HEADERS: &str =
    "Authorization, Content-Type, X-Guard-Dashboard-Session, X-Guard-Token";
const ACTIVITY_INTERVAL: Duration = Duration::from_millis(500);
const ACTIVITY_WRITE_TIMEOUT: Duration = Duration::from_millis(10);
const MAX_BUSY_TIMEOUT_MS: u64 = 60_000;
const MAX_READ_STATE_PAGES: usize = 100_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Handshake {
    schema: String,
    auth_token: String,
    guard_home: String,
    store_path: String,
    source: String,
    busy_timeout_ms: u64,
    #[serde(default)]
    dashboard_build: Option<String>,
    #[serde(default)]
    user_home: Option<String>,
}

pub(super) struct ReadConfig {
    token: Vec<u8>,
    guard_home: String,
    store_path: String,
    source: String,
    busy_timeout_ms: u64,
    dashboard_build: Option<String>,
    /// `str(Path.home())` in the daemon, which evidence reads shorten to `~`.
    user_home: Option<String>,
}

impl ReadConfig {
    fn from_line(line: &[u8]) -> Option<Self> {
        let handshake: Handshake = serde_json::from_slice(line).ok()?;
        if handshake.schema != HANDSHAKE_SCHEMA
            || handshake.auth_token.is_empty()
            || !handshake.auth_token.is_ascii()
            || !Path::new(&handshake.guard_home).is_absolute()
            || !Path::new(&handshake.store_path).is_absolute()
            || handshake.source.is_empty()
            || !(1..=MAX_BUSY_TIMEOUT_MS).contains(&handshake.busy_timeout_ms)
        {
            return None;
        }
        let dashboard_build = handshake.dashboard_build.filter(|build| {
            !build.is_empty()
                && build.len() <= 64
                && build.bytes().all(|b| b.is_ascii_alphanumeric())
        });
        Some(Self {
            token: handshake.auth_token.into_bytes(),
            guard_home: handshake.guard_home,
            store_path: handshake.store_path,
            source: handshake.source,
            busy_timeout_ms: handshake.busy_timeout_ms,
            dashboard_build,
            user_home: handshake.user_home,
        })
    }
}

/// What the edge knows from its daemon: the handshake, once it arrives, and
/// the socket that reports answered requests back.
pub(super) struct NativeReads {
    config: RwLock<Option<Arc<ReadConfig>>>,
    activity: Option<UnixStream>,
    last_activity: Mutex<Option<Instant>>,
    request_ids: AtomicU64,
}

impl NativeReads {
    pub(super) fn new(activity: Option<UnixStream>) -> Self {
        // The timeout covers only writes, so the parent watcher's reads on the
        // same socket keep blocking.
        let activity = activity.filter(|socket| {
            socket
                .set_write_timeout(Some(ACTIVITY_WRITE_TIMEOUT))
                .is_ok()
        });
        Self {
            config: RwLock::new(None),
            activity,
            last_activity: Mutex::new(None),
            request_ids: AtomicU64::new(0),
        }
    }

    /// Takes one handshake line from the daemon. A line that does not parse
    /// leaves the current configuration, if any, in place.
    pub(super) fn accept_handshake(&self, line: &[u8]) {
        if let Some(config) = ReadConfig::from_line(line) {
            *self
                .config
                .write()
                .unwrap_or_else(|poison| poison.into_inner()) = Some(Arc::new(config));
        }
    }

    pub(super) fn config(&self) -> Option<Arc<ReadConfig>> {
        self.config
            .read()
            .unwrap_or_else(|poison| poison.into_inner())
            .clone()
    }

    fn report_activity(&self) {
        let Some(activity) = &self.activity else {
            return;
        };
        {
            let mut last = self
                .last_activity
                .lock()
                .unwrap_or_else(|poison| poison.into_inner());
            let now = Instant::now();
            if last.is_some_and(|at| now.duration_since(at) < ACTIVITY_INTERVAL) {
                return;
            }
            *last = Some(now);
        }
        // A daemon that is not reading loses a heartbeat, not a request: the
        // write gives up after `ACTIVITY_WRITE_TIMEOUT`.
        let mut writer = activity;
        let _ = writer.write_all(b"a");
    }

    fn store_call(&self, config: &ReadConfig, method: &str, args: Value) -> Option<Value> {
        let Value::Object(args) = args else {
            return None;
        };
        let wait = Duration::from_millis(config.busy_timeout_ms);
        let _gate =
            crate::hook_evidence_store_gate::hold_storage_gate(Path::new(&config.guard_home), wait)
                .ok()?;
        let request = GuardStoreRequestV1 {
            schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
            request_id: format!(
                "daemon-edge-{}",
                self.request_ids.fetch_add(1, Ordering::Relaxed)
            ),
            store_path: config.store_path.clone(),
            guard_home: config.guard_home.clone(),
            method: method.to_owned(),
            source: config.source.clone(),
            busy_timeout_ms: config.busy_timeout_ms,
            args,
        };
        crate::guard_store_op::evaluate(&request)
            .ok()
            .map(|(payload, _)| payload)
    }
}

/// The edge either answered the connection or hands back the bytes it read,
/// which must reach the daemon before anything else.
pub(super) enum Outcome {
    Answered,
    Relay(Vec<u8>),
}

pub(super) fn answer(
    client: &TcpStream,
    config: &ReadConfig,
    reads: &NativeReads,
    stalled_write: Duration,
) -> Outcome {
    let Some(head) = take_head(client) else {
        return Outcome::Relay(Vec::new());
    };
    let Some((status, body, cors_origin, no_store)) =
        parse_get(&head).and_then(|request| respond(&request, config, reads))
    else {
        return Outcome::Relay(head);
    };
    let response = json_response(
        status,
        &body,
        config.dashboard_build.as_deref(),
        cors_origin.as_deref(),
        no_store,
    );
    let mut writer = client;
    let _ = client.set_write_timeout(Some(stalled_write));
    let _ = writer.write_all(&response);
    let _ = client.shutdown(Shutdown::Both);
    reads.report_activity();
    Outcome::Answered
}

/// The client's whole head, read off the socket only once a peek shows it
/// has fully arrived with nothing after it. `None` leaves every byte unread.
fn take_head(client: &TcpStream) -> Option<Vec<u8>> {
    let peeked = peek_head(client);
    let _ = client.set_read_timeout(None);
    let mut head = peeked?;
    let mut reader = client;
    reader.read_exact(&mut head).ok()?;
    Some(head)
}

/// A zeroed buffer as long as the complete head waiting on `client`.
fn peek_head(client: &TcpStream) -> Option<Vec<u8>> {
    let deadline = Instant::now() + HEAD_PEEK_WINDOW;
    let mut buffer = vec![0u8; MAX_HEAD_BYTES];
    let mut seen = 0;
    let peeked = loop {
        let remaining = deadline.checked_duration_since(Instant::now())?;
        if remaining.is_zero() || client.set_read_timeout(Some(remaining)).is_err() {
            return None;
        }
        let peeked = match client.peek(&mut buffer) {
            Ok(0) => return None,
            Ok(peeked) => peeked,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        };
        if head_end(&buffer[..peeked]).is_some() || peeked == buffer.len() {
            break peeked;
        }
        // A peek returns at once while any bytes wait, so pause rather than
        // spin until more of the head arrives.
        if peeked == seen {
            std::thread::sleep(HEAD_PEEK_PAUSE);
        }
        seen = peeked;
    };
    // Bytes after the head belong to a body or a pipelined request: only the
    // daemon reads those.
    (head_end(&buffer[..peeked])? == peeked).then(|| vec![0u8; peeked])
}

fn respond(
    request: &GetRequest<'_>,
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<(u16, Value, Option<String>, bool)> {
    if request.has_header("Content-Length") || request.has_header("Transfer-Encoding") {
        return None;
    }
    let caller = authorize(request, &config.token)?;
    // Reported at the start as well as the end, so a slow store read never
    // looks idle to the daemon.
    reads.report_activity();
    if request.path == "/v1/requests" {
        let hosted = caller.cors_origin.as_deref().is_some_and(|origin| {
            matches!(
                origin_decision(origin, "/"),
                DaemonRoutePayloadV1::Origin {
                    hosted_origin: true,
                    ..
                }
            )
        });
        return requests::list(request.query, hosted, config, reads)
            .map(|(status, body, no_store)| (status, body, caller.cors_origin, no_store));
    }
    route(request.path, request.query, config, reads)
        .map(|(status, body)| (status, body, caller.cors_origin, false))
}

/// The answer the daemon's Python route gives for the same path and query, or
/// `None` for a path it does not serve here or a query it does not read the
/// same way.
fn route(
    path: &str,
    query: &str,
    config: &ReadConfig,
    reads: &NativeReads,
) -> Option<(u16, Value)> {
    let not_found = || (404, json!({"error": "not_found"}));
    match path {
        "/v1/receipts" => {
            let limit = query_int(query, "limit", 200).ok()?.clamp(1, 500);
            let harness = query_value(query, "harness").ok()?;
            let items = reads.store_call(
                config,
                "list_receipts",
                json!({"limit": limit, "harness": harness}),
            )?;
            items.is_array().then(|| (200, json!({"items": items})))
        }
        "/v1/receipts/latest" => {
            let harness = query_value(query, "harness").ok()?;
            let artifact_id = query_value(query, "artifact_id").ok()?;
            let (Some(harness), Some(artifact_id)) = (harness, artifact_id) else {
                return Some((400, json!({"error": "missing_receipt_query"})));
            };
            let receipt = reads.store_call(
                config,
                "get_latest_receipt",
                json!({"harness": harness, "artifact_id": artifact_id}),
            )?;
            Some(if receipt.is_null() {
                not_found()
            } else {
                (200, receipt)
            })
        }
        "/v1/read-state" => read_state(config, reads).map(|ids| (200, json!({"ids": ids}))),
        "/v1/evidence" => evidence::list(query, config, reads),
        "/v1/sessions" => records::sessions(config, reads),
        "/v1/command-activity" => activity::list(query, config, reads),
        "/v1/command-activity/analytics" => activity::analytics(query, config, reads),
        "/v1/connect/state" => Some((
            410,
            json!({
                "error": "legacy_pairing_disabled",
                "message": "Use hol-guard connect for browser OAuth.",
            }),
        )),
        "/v1/receipts/analytics" => records::receipt_analytics(query, config, reads),
        _ => {
            if let Some(operation_id) = single_segment(path, "/v1/operations/", "") {
                return records::operation(operation_id, config, reads);
            }
            // The daemon serves `/v1/receipts/analytics` itself, ahead of its
            // receipt lookup.
            if let Some(receipt_id) =
                single_segment(path, "/v1/receipts/", "").filter(|segment| *segment != "analytics")
            {
                let receipt =
                    reads.store_call(config, "get_receipt", json!({"receipt_id": receipt_id}))?;
                return Some(if receipt.is_null() {
                    not_found()
                } else {
                    (200, receipt)
                });
            }
            let artifact_id = single_segment(path, "/v1/artifacts/", "/diff")?;
            let Some(harness) = query_value(query, "harness").ok()? else {
                return Some((400, json!({"error": "missing_harness"})));
            };
            let diff = reads.store_call(
                config,
                "artifact_latest_diff",
                json!({"harness": harness, "artifact_id": artifact_id}),
            )?;
            Some(if diff.is_object() {
                (200, diff)
            } else {
                not_found()
            })
        }
    }
}

/// The one path segment between `prefix` and `suffix`.
fn single_segment<'a>(path: &'a str, prefix: &str, suffix: &str) -> Option<&'a str> {
    let segment = path.strip_prefix(prefix)?.strip_suffix(suffix)?;
    (!segment.is_empty() && !segment.contains('/')).then_some(segment)
}

/// Read request ids, most recently read first, as `get_read_state` pages and
/// orders them.
fn read_state(config: &ReadConfig, reads: &NativeReads) -> Option<Vec<Value>> {
    let mut marks: Vec<(String, String)> = Vec::new();
    let mut after = Value::Null;
    for _ in 0..MAX_READ_STATE_PAGES {
        let page = reads.store_call(config, "get_read_state", json!({"after": after}))?;
        for mark in page.get("marks")?.as_array()? {
            let [request_id, read_at] = mark.as_array()?.as_slice() else {
                return None;
            };
            marks.push((
                request_id.as_str()?.to_owned(),
                read_at.as_str()?.to_owned(),
            ));
        }
        after = page.get("after")?.clone();
        if after.is_null() {
            marks.sort_by(|left, right| right.1.cmp(&left.1));
            return Some(marks.into_iter().map(|(id, _)| Value::from(id)).collect());
        }
    }
    None
}

/// The response the daemon's `_write_json` writes: HTML-safe JSON, `nosniff`,
/// the dashboard build stamp and, for an allowed `Origin`, its CORS headers.
pub(super) fn json_response(
    status: u16,
    body: &Value,
    dashboard_build: Option<&str>,
    cors_origin: Option<&str>,
    no_store: bool,
) -> Vec<u8> {
    let encoded = serde_json::to_vec(body).unwrap_or_else(|_| b"null".to_vec());
    let mut escaped = Vec::with_capacity(encoded.len());
    for byte in encoded {
        match byte {
            b'&' => escaped.extend_from_slice(b"\\u0026"),
            b'<' => escaped.extend_from_slice(b"\\u003c"),
            b'>' => escaped.extend_from_slice(b"\\u003e"),
            byte => escaped.push(byte),
        }
    }
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        410 => "Gone",
        _ => "Not Found",
    };
    let mut response = format!(
        "HTTP/1.0 {status} {reason}\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: {}\r\nX-Content-Type-Options: nosniff\r\n",
        escaped.len()
    );
    if let Some(origin) = cors_origin {
        response.push_str(&format!(
            "Access-Control-Allow-Origin: {origin}\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: {CORS_ALLOW_HEADERS}\r\nAccess-Control-Allow-Private-Network: true\r\nVary: Origin\r\n"
        ));
    }
    if let Some(build) = dashboard_build {
        response.push_str(&format!("X-Guard-Dashboard-Build: {build}\r\n"));
    }
    if no_store {
        response.push_str("Cache-Control: no-store\r\n");
    }
    response.push_str("Connection: close\r\n\r\n");
    let mut bytes = response.into_bytes();
    bytes.extend_from_slice(&escaped);
    bytes
}

#[path = "daemon_edge_evidence.rs"]
mod evidence;

#[path = "daemon_edge_records.rs"]
mod records;

#[path = "daemon_edge_activity.rs"]
mod activity;

#[path = "daemon_edge_requests.rs"]
mod requests;

#[cfg(test)]
#[path = "daemon_edge_reads_tests.rs"]
mod tests;
