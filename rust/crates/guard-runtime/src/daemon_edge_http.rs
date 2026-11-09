//! The narrow slice of HTTP the daemon edge reads before it relays.
//!
//! The edge answers a request itself only when this module reads it the same
//! way the daemon's Python server would. Anything it cannot read exactly, such
//! as a percent-encoded path, a folded header or a body on anything but a
//! `POST`, makes the parser give up, and the edge then relays the untouched
//! bytes to the daemon.

use std::io::{self, Read};
use std::net::TcpStream;
use std::time::{Duration, Instant};

const MAX_HEAD_BYTES: usize = 16 * 1024;
/// The largest `POST` body the edge reads; a larger one goes to the daemon.
pub(super) const MAX_BODY_BYTES: usize = 64 * 1024;
// A client that has not sent its whole request this soon after the edge
// accepted it goes to the daemon untouched, so the daemon's own
// partial-header admission and deadlines see it as before.
pub(super) const HEAD_PEEK_WINDOW: Duration = Duration::from_millis(25);
const HEAD_PEEK_PAUSE: Duration = Duration::from_millis(1);

/// A request head the edge can answer: a plain `GET`, or a `POST` or
/// `DELETE` whose body the edge reads separately.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct Request<'a> {
    pub(super) method: &'a str,
    pub(super) path: &'a str,
    pub(super) query: &'a str,
    headers: Vec<(&'a str, &'a str)>,
}

impl<'a> Request<'a> {
    /// The value of a header that appears exactly once, or `None` when it is
    /// absent or repeated.
    pub(super) fn single_header(&self, name: &str) -> Option<&'a str> {
        let mut values = self
            .headers
            .iter()
            .filter(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| *value);
        let first = values.next()?;
        values.next().is_none().then_some(first)
    }

    pub(super) fn has_header(&self, name: &str) -> bool {
        self.headers
            .iter()
            .any(|(header, _)| header.eq_ignore_ascii_case(name))
    }
}

/// The end of the head (after its blank line), once `bytes` holds all of it.
pub(super) fn head_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|start| start + 4)
}

/// Reads a complete request head, or `None` when it is anything but a plain
/// `GET` with a path the edge can match byte for byte.
#[cfg(test)]
pub(super) fn parse_get(head: &[u8]) -> Option<Request<'_>> {
    parse_request(head).filter(|request| request.method == "GET")
}

/// Reads a complete `GET`, `POST` or `DELETE` head the way `parse_get` reads
/// a `GET`.
pub(super) fn parse_request(head: &[u8]) -> Option<Request<'_>> {
    let text = std::str::from_utf8(head.strip_suffix(b"\r\n\r\n")?).ok()?;
    if !text.is_ascii() {
        return None;
    }
    let mut lines = text.split("\r\n");
    let mut request_line = lines.next()?.split(' ');
    let (method, target, version) = (
        request_line.next()?,
        request_line.next()?,
        request_line.next()?,
    );
    if request_line.next().is_some()
        || !matches!(method, "GET" | "POST" | "DELETE")
        || !matches!(version, "HTTP/1.0" | "HTTP/1.1")
    {
        return None;
    }
    let (path, query) = target.split_once('?').unwrap_or((target, ""));
    if !plain_path(path)
        || !query
            .bytes()
            .all(|byte| byte.is_ascii_graphic() && byte != b'#')
    {
        return None;
    }
    let mut headers = Vec::new();
    for line in lines {
        if line.starts_with([' ', '\t']) || line.contains(['\r', '\n']) {
            return None;
        }
        let (name, value) = line.split_once(':')?;
        if name.is_empty() || !name.bytes().all(is_token_byte) {
            return None;
        }
        // As Python's header parser does: leading blanks go, trailing ones stay.
        headers.push((name, value.trim_start_matches([' ', '\t'])));
    }
    Some(Request {
        method,
        path,
        query,
        headers,
    })
}

/// An absolute path of plain segments: no empty segment, no trailing slash
/// and nothing a URL parser could decode, split or reinterpret.
fn plain_path(path: &str) -> bool {
    let Some(rest) = path.strip_prefix('/') else {
        return false;
    };
    !rest.is_empty()
        && rest.split('/').all(|segment| {
            !segment.is_empty()
                && segment
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        })
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

/// The last non-empty value of `key`, decoded as Python's `parse_qs` decodes
/// it. `Err` means the query holds an escape the edge will not guess at.
pub(super) fn query_value(query: &str, key: &str) -> Result<Option<String>, ()> {
    let mut found = None;
    for field in query.split('&') {
        let Some((name, value)) = field.split_once('=') else {
            continue;
        };
        if value.is_empty() {
            continue;
        }
        if decode_component(name)? == key {
            found = Some(decode_component(value)?);
        }
    }
    Ok(found)
}

/// Every field, decoded as `parse_qsl(query, keep_blank_values=True)`
/// decodes it. `Err` means a field holds an escape the edge will not guess at.
pub(super) fn query_pairs(query: &str) -> Result<Vec<(String, String)>, ()> {
    query
        .split('&')
        .filter(|field| !field.is_empty())
        .map(|field| {
            let (name, value) = field.split_once('=').unwrap_or((field, ""));
            Ok((decode_component(name)?, decode_component(value)?))
        })
        .collect()
}

fn decode_component(text: &str) -> Result<String, ()> {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => decoded.push(b' '),
            b'%' => {
                let pair = bytes.get(index + 1..index + 3).ok_or(())?;
                let pair = std::str::from_utf8(pair).map_err(|_| ())?;
                decoded.push(u8::from_str_radix(pair, 16).map_err(|_| ())?);
                index += 2;
            }
            byte => decoded.push(byte),
        }
        index += 1;
    }
    String::from_utf8(decoded).map_err(|_| ())
}

/// A query integer as Python's `int()` reads plain decimal text. `Err` for any
/// other spelling, whose Python reading the edge does not reproduce.
pub(super) fn query_int(query: &str, key: &str, default: i64) -> Result<i64, ()> {
    let Some(value) = query_value(query, key)? else {
        return Ok(default);
    };
    let digits = value.strip_prefix('-').unwrap_or(&value);
    if digits.is_empty() || digits.len() > 18 || !digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return Err(());
    }
    value.parse().map_err(|_| ())
}

/// The client's whole request and the length of its head, read off the
/// socket only once a peek shows it has fully arrived with nothing after it.
/// `None` leaves every byte unread.
pub(super) fn take_request(client: &TcpStream) -> Option<(Vec<u8>, usize)> {
    let peeked = peek_request(client);
    let _ = client.set_read_timeout(None);
    let (mut bytes, head_len) = peeked?;
    let mut reader = client;
    reader.read_exact(&mut bytes).ok()?;
    Some((bytes, head_len))
}

/// A zeroed buffer as long as the complete request waiting on `client`, and
/// the length of its head.
fn peek_request(client: &TcpStream) -> Option<(Vec<u8>, usize)> {
    let deadline = Instant::now() + HEAD_PEEK_WINDOW;
    let mut buffer = vec![0u8; MAX_HEAD_BYTES + MAX_BODY_BYTES];
    let mut seen = 0;
    loop {
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
        if let Some(head_len) = head_end(&buffer[..peeked.min(MAX_HEAD_BYTES)]) {
            let total = head_len + declared_body(&buffer[..head_len])?;
            // Bytes after the request belong to a pipelined one: only the
            // daemon reads those.
            match peeked.cmp(&total) {
                std::cmp::Ordering::Equal => return Some((vec![0u8; total], head_len)),
                std::cmp::Ordering::Greater => return None,
                std::cmp::Ordering::Less => {}
            }
        } else if peeked >= MAX_HEAD_BYTES {
            return None;
        }
        // A peek returns at once while any bytes wait, so pause rather than
        // spin until more of the request arrives.
        if peeked == seen {
            std::thread::sleep(HEAD_PEEK_PAUSE);
        }
        seen = peeked;
    }
}

/// The body length a head declares: none for a `GET`, and one plain decimal
/// `Content-Length` no longer than the edge reads for a `POST`, or for a
/// `DELETE` that has one. `None` for any other head, which goes to the daemon
/// untouched.
fn declared_body(head: &[u8]) -> Option<usize> {
    let request = parse_request(head)?;
    match request.method {
        "GET" => return Some(0),
        "DELETE" if !request.has_header("Content-Length") => return Some(0),
        _ => {}
    }
    let length = request.single_header("Content-Length")?;
    if length.is_empty() || length.len() > 7 || !length.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let length: usize = length.parse().ok()?;
    (length <= MAX_BODY_BYTES).then_some(length)
}
