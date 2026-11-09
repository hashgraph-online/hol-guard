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
use super::{authorize, NativeReads, ReadConfig, CORS_ALLOW_HEADERS};

const EVENTS_PATH: &str = "/v1/events/stream";
const ACTIVITY_PATH: &str = "/v1/command-activity/events";
const POLL_INTERVAL: Duration = Duration::from_millis(500);
const PAGE_LIMIT: i64 = 100;
/// `_COMMAND_ACTIVITY_STREAM_MAX_CLIENTS`.
const ACTIVITY_MAX_CLIENTS: usize = 8;
/// `_COMMAND_ACTIVITY_STREAM_MAX_SECONDS`.
const ACTIVITY_MAX_DURATION: Duration = Duration::from_secs(300);

static ACTIVITY_CLIENTS: AtomicUsize = AtomicUsize::new(0);

/// Which stream a request opens, and from where.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum Stream {
    Events { cursor: i64 },
    Activity { cursor: i64 },
}

/// Whether the edge streams this request itself. `None` leaves it to the
/// daemon: a different path, a query key the daemon audits (`token`), a
/// caller it would refuse, or a cursor it answers with an error.
pub(super) fn opens(
    request: &Request<'_>,
    config: &ReadConfig,
) -> Option<(Stream, Option<String>)> {
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
        Stream::Activity {
            cursor: activity_cursor(&pairs, request.single_header("Last-Event-ID"))?,
        }
    };
    Some((stream, caller.cors_origin))
}

/// `parse_command_activity_event_cursor`: `Last-Event-ID` wins over a lone
/// `cursor` field, and the value must be a non-negative 64-bit integer.
pub(super) fn activity_cursor(
    pairs: &[(String, String)],
    last_event_id: Option<&str>,
) -> Option<i64> {
    if pairs.iter().any(|(key, _)| key != "cursor") {
        return None;
    }
    let cursors: Vec<&str> = pairs.iter().map(|(_, value)| value.as_str()).collect();
    if cursors.len() > 1 {
        return None;
    }
    let candidate = match last_event_id
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        Some(value) => value,
        None => cursors.first().copied().unwrap_or("0"),
    };
    if candidate.is_empty() || !candidate.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    candidate.parse::<i64>().ok()
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

/// Streams until the client stops reading. Returns `false` without writing
/// anything when the command-activity stream already has its full number of
/// clients, so the daemon can answer 429.
pub(super) fn serve(
    client: &TcpStream,
    stream: Stream,
    cors_origin: Option<&str>,
    config: &ReadConfig,
    reads: &NativeReads,
    stalled_write: Duration,
) -> bool {
    let _slot = match stream {
        Stream::Activity { .. } => match ActivitySlot::claim() {
            Some(slot) => Some(slot),
            None => return false,
        },
        Stream::Events { .. } => None,
    };
    let _ = client.set_write_timeout(Some(stalled_write));
    let mut writer = client;
    if writer.write_all(&stream_head(cors_origin)).is_ok() {
        match stream {
            Stream::Events { cursor } => events(writer, cursor, config, reads),
            Stream::Activity { cursor } => activity(writer, cursor, config, reads),
        }
    }
    let _ = client.shutdown(Shutdown::Both);
    true
}

fn events(mut writer: &TcpStream, mut cursor: i64, config: &ReadConfig, reads: &NativeReads) {
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
        if !frames.is_empty() && writer.write_all(&frames).is_err() {
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

fn activity(mut writer: &TcpStream, cursor: i64, config: &ReadConfig, reads: &NativeReads) {
    let deadline = Instant::now() + ACTIVITY_MAX_DURATION;
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
        if !frames.is_empty() && writer.write_all(&frames).is_err() {
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

#[cfg(test)]
#[path = "daemon_edge_streams_tests.rs"]
mod tests;
