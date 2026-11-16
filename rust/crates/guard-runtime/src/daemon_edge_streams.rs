//! `GET /v1/events/stream` and `GET /v1/command-activity/events`, streamed
//! as `_stream_events` and `stream_command_activity_events` stream them: the
//! store is polled every half second and each new row is written as one
//! server-sent event until the client goes away (or, for command activity,
//! until five minutes pass).

use std::io::Write;
use std::net::{Shutdown, TcpStream};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::{json, Value};

use super::super::http::{query_pairs, Request};
use super::{authorize, json_response, NativeReads, ReadConfig, CORS_ALLOW_HEADERS};

const EVENTS_PATH: &str = "/v1/events/stream";
const ACTIVITY_PATH: &str = "/v1/command-activity/events";
const POLL_INTERVAL: Duration = Duration::from_millis(500);
const PAGE_LIMIT: i64 = 100;
/// `_COMMAND_ACTIVITY_STREAM_MAX_CLIENTS`.
const ACTIVITY_MAX_CLIENTS: usize = 8;
/// `_COMMAND_ACTIVITY_STREAM_MAX_SECONDS`.
const ACTIVITY_MAX_DURATION: Duration = Duration::from_secs(300);
/// How long a stream may go without a write. An SSE comment then goes out,
/// so a client that went away fails the write and frees its slot.
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const KEEPALIVE_FRAME: &[u8] = b":\n\n";

static ACTIVITY_CLIENTS: AtomicUsize = AtomicUsize::new(0);

/// Which stream a request opens, and from where.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Stream {
    Events { cursor: i64 },
    Activity { cursor: i64 },
}

/// A stream to serve and the CORS origin to name.
type Opened = (Stream, Option<String>);

/// The streaming answer for this request: `Ok` to stream, `Err` for the 400
/// the daemon answers a malformed command-activity query with. `None` leaves
/// the request to the edge's other routes: a different path, a query key the
/// refusals audit (`token`), or a caller they refuse.
pub(super) fn opens(request: &Request<'_>, config: &ReadConfig) -> Option<Result<Opened, Vec<u8>>> {
    if request.method != "GET" || !matches!(request.path, EVENTS_PATH | ACTIVITY_PATH) {
        return None;
    }
    if request.has_header("Content-Length") || request.has_header("Transfer-Encoding") {
        return None;
    }
    let pairs = query_pairs(request.query).ok()?;
    if pairs.iter().any(|(key, _)| key == "token") {
        return None;
    }
    let caller = authorize(request, &config.token)?;
    let stream = if request.path == EVENTS_PATH {
        let (_, _, _, fields) =
            crate::daemon_handler_requests::events_cursor(request.query).into_parts();
        Stream::Events {
            cursor: fields.get("cursor").and_then(Value::as_i64)?,
        }
    } else {
        match activity_cursor(
            request.query,
            &pairs,
            request.single_header("Last-Event-ID"),
        ) {
            Ok(cursor) => Stream::Activity { cursor },
            Err(code) => {
                return Some(Err(json_response(
                    400,
                    &json!({ "error": code }),
                    config.dashboard_build.as_deref(),
                    caller.cors_origin.as_deref(),
                    false,
                )))
            }
        }
    };
    Some(Ok((stream, caller.cors_origin)))
}

/// `parse_command_activity_event_cursor`: `Last-Event-ID` wins over a lone
/// `cursor` field, and the value must be a non-negative 64-bit integer. The
/// error is the code the daemon answers with.
pub(super) fn activity_cursor(
    query: &str,
    pairs: &[(String, String)],
    last_event_id: Option<&str>,
) -> Result<i64, &'static str> {
    if query.len() > 8_192 {
        return Err("query_too_long");
    }
    let mut cursor = None;
    for (key, value) in pairs {
        if key != "cursor" {
            return Err("unknown_query_parameter");
        }
        if cursor.is_some() || value.is_empty() {
            return Err("invalid_query_parameter");
        }
        cursor = Some(value.as_str());
    }
    let candidate = match last_event_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(value) => value,
        None => cursor.unwrap_or("0"),
    };
    if candidate.is_empty() || !candidate.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err("invalid_cursor");
    }
    candidate.parse::<i64>().map_err(|_| "invalid_cursor")
}

pub(super) fn stream_head(cors_origin: Option<&str>) -> Vec<u8> {
    let mut head = String::from(
        "HTTP/1.0 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nConnection: keep-alive\r\n",
    );
    if let Some(origin) = cors_origin {
        head.push_str(&format!(
            "Access-Control-Allow-Origin: {origin}\r\nAccess-Control-Allow-Methods: GET, OPTIONS\r\nAccess-Control-Allow-Headers: {CORS_ALLOW_HEADERS}\r\nAccess-Control-Allow-Private-Network: true\r\nVary: Origin\r\n"
        ));
    }
    head.push_str("\r\n");
    head.into_bytes()
}

/// Streams until the client stops reading. When the command-activity stream
/// already has its full number of clients, answers 429 as the daemon does.
pub(super) fn serve(
    client: &TcpStream,
    stream: Stream,
    cors_origin: Option<&str>,
    config: &ReadConfig,
    reads: &NativeReads,
    stalled_write: Duration,
) {
    let _ = client.set_write_timeout(Some(stalled_write));
    let mut writer = client;
    let slot = match stream {
        Stream::Activity { .. } => ActivitySlot::claim().map(Some),
        Stream::Events { .. } => Some(None),
    };
    match slot {
        None => {
            let _ = writer.write_all(&too_many_streams(config, cors_origin));
        }
        Some(_slot) => {
            if writer.write_all(&stream_head(cors_origin)).is_ok() {
                match stream {
                    Stream::Events { cursor } => events(writer, cursor, config, reads),
                    Stream::Activity { cursor } => activity(writer, cursor, config, reads),
                }
            }
        }
    }
    let _ = client.shutdown(Shutdown::Both);
}

/// `_write_json({"error": "too_many_streams"}, status=429)`.
pub(super) fn too_many_streams(config: &ReadConfig, cors_origin: Option<&str>) -> Vec<u8> {
    json_response(
        429,
        &json!({"error": "too_many_streams"}),
        config.dashboard_build.as_deref(),
        cors_origin,
        false,
    )
}

/// Writes `frames`, or a keepalive comment once the stream has been quiet
/// for `KEEPALIVE_INTERVAL`. `false` once the client is gone.
fn write_frames(mut writer: &TcpStream, frames: &[u8], last_write: &mut Instant) -> bool {
    let bytes = if !frames.is_empty() {
        frames
    } else if last_write.elapsed() >= KEEPALIVE_INTERVAL {
        KEEPALIVE_FRAME
    } else {
        return true;
    };
    if writer.write_all(bytes).is_err() {
        return false;
    }
    *last_write = Instant::now();
    true
}

fn events(writer: &TcpStream, mut cursor: i64, config: &ReadConfig, reads: &NativeReads) {
    let mut last_write = Instant::now();
    loop {
        reads.report_activity();
        let items = reads
            .store_call(
                config,
                "list_events_after",
                json!({"event_id": cursor, "limit": PAGE_LIMIT}),
            )
            .and_then(|items| items.as_array().cloned())
            .unwrap_or_default();
        let (frames, next) = event_frames(&items, cursor);
        cursor = next;
        if !write_frames(writer, &frames, &mut last_write) {
            return;
        }
        thread::sleep(POLL_INTERVAL);
    }
}

/// One `data:` frame per event row with an integer id, and the cursor after
/// the last of them.
pub(super) fn event_frames(items: &[Value], mut cursor: i64) -> (Vec<u8>, i64) {
    let mut frames = Vec::new();
    for item in items {
        let Some(event_id) = item.get("event_id").and_then(Value::as_i64) else {
            continue;
        };
        cursor = event_id;
        frames.extend_from_slice(b"data: ");
        frames.extend_from_slice(python_json(item).as_bytes());
        frames.extend_from_slice(b"\n\n");
    }
    (frames, cursor)
}

fn activity(writer: &TcpStream, cursor: i64, config: &ReadConfig, reads: &NativeReads) {
    let deadline = Instant::now() + ACTIVITY_MAX_DURATION;
    let mut last_write = Instant::now();
    let mut cursor = cursor.max(0);
    while Instant::now() < deadline {
        reads.report_activity();
        let page = reads
            .store_call(
                config,
                "list_command_activity_invalidations",
                json!({"cursor": cursor, "limit": PAGE_LIMIT}),
            )
            .unwrap_or(Value::Null);
        let (frames, next) = activity_frames(&page, cursor);
        cursor = next;
        if !write_frames(writer, &frames, &mut last_write) {
            return;
        }
        thread::sleep(POLL_INTERVAL);
    }
}

/// The reset frame a page asks for, then one frame per invalidation.
pub(super) fn activity_frames(page: &Value, mut cursor: i64) -> (Vec<u8>, i64) {
    let mut frames = String::new();
    if page.get("reset_required") == Some(&Value::Bool(true)) {
        if let Some(reset) = page.get("reset_cursor").and_then(Value::as_i64) {
            cursor = reset;
            frames.push_str(&format!(
                "id: {reset}\nevent: command_activity_reset\ndata: {{\"event\":\"command_activity_reset\",\"reset_required\":true}}\n\n"
            ));
        }
    }
    let items = page
        .get("items")
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .unwrap_or_default();
    for item in items {
        let (Some(sequence), Some(activity_id)) = (
            item.get("sequence").and_then(Value::as_i64),
            item.get("activity_id").and_then(Value::as_str),
        ) else {
            continue;
        };
        cursor = sequence;
        let body = json!({"event": "command_activity_invalidated", "activity_id": activity_id});
        frames.push_str(&format!("id: {sequence}\ndata: {body}\n\n"));
    }
    (frames.into_bytes(), cursor)
}

/// `json.dumps(item)` with its default separators and ASCII escaping.
pub(super) fn python_json(value: &Value) -> String {
    let mut out = String::new();
    write_python(value, &mut out);
    out
}

fn write_python(value: &Value, out: &mut String) {
    match value {
        Value::Array(items) => {
            out.push('[');
            for (index, item) in items.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                write_python(item, out);
            }
            out.push(']');
        }
        Value::Object(map) => {
            out.push('{');
            for (index, (key, item)) in map.iter().enumerate() {
                if index > 0 {
                    out.push_str(", ");
                }
                write_python_string(key, out);
                out.push_str(": ");
                write_python(item, out);
            }
            out.push('}');
        }
        Value::String(text) => write_python_string(text, out),
        other => out.push_str(&other.to_string()),
    }
}

fn write_python_string(text: &str, out: &mut String) {
    out.push('"');
    for character in text.chars() {
        match character {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            character if (character as u32) < 0x20 || (character as u32) > 0x7f => {
                let mut units = [0u16; 2];
                for unit in character.encode_utf16(&mut units) {
                    out.push_str(&format!("\\u{unit:04x}"));
                }
            }
            character => out.push(character),
        }
    }
    out.push('"');
}

struct ActivitySlot;

impl ActivitySlot {
    fn claim() -> Option<Self> {
        ACTIVITY_CLIENTS
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |active| {
                (active < ACTIVITY_MAX_CLIENTS).then_some(active + 1)
            })
            .ok()
            .map(|_| Self)
    }
}

impl Drop for ActivitySlot {
    fn drop(&mut self) {
        ACTIVITY_CLIENTS.fetch_sub(1, Ordering::AcqRel);
    }
}

#[cfg(all(test, unix))]
#[path = "daemon_edge_streams_tests.rs"]
mod tests;
