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

    /// The first value of a header, as `email.message.Message.get` reads it.
    pub(super) fn first_header(&self, name: &str) -> Option<&'a str> {
        self.headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| *value)
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
/// it: an escape that does not decode stays as written and bytes that are not
/// UTF-8 become U+FFFD. Never `Err`; the `Result` keeps the callers' shape.
pub(super) fn query_value(query: &str, key: &str) -> Result<Option<String>, ()> {
    Ok(parse_qs(query)
        .into_iter()
        .filter(|(name, _)| name == key)
        .map(|(_, value)| value)
        .next_back())
}

/// Every field, decoded as `parse_qsl(query, keep_blank_values=True)`
/// decodes it. Never `Err`; the `Result` keeps the callers' shape.
pub(super) fn query_pairs(query: &str) -> Result<Vec<(String, String)>, ()> {
    Ok(query
        .split('&')
        .filter(|field| !field.is_empty())
        .map(|field| {
            let (name, value) = field.split_once('=').unwrap_or((field, ""));
            (unquote_plus(name), unquote_plus(value))
        })
        .collect())
}

/// `parse_qs(text)` without blank values, in order: an escape that does not
/// decode stays as written and bytes that are not UTF-8 become U+FFFD, as
/// `unquote` leaves them.
pub(super) fn parse_qs(text: &str) -> Vec<(String, String)> {
    text.split('&')
        .filter(|field| !field.is_empty())
        .filter_map(|field| {
            let (name, value) = field.split_once('=')?;
            let value = unquote_plus(value);
            (!value.is_empty()).then(|| (unquote_plus(name), value))
        })
        .collect()
}

fn unquote_plus(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        let escaped = (bytes[index] == b'%')
            .then(|| bytes.get(index + 1..index + 3))
            .flatten()
            .filter(|pair| pair.iter().all(u8::is_ascii_hexdigit))
            .and_then(|pair| std::str::from_utf8(pair).ok())
            .and_then(|pair| u8::from_str_radix(pair, 16).ok());
        match escaped {
            Some(value) => {
                decoded.push(value);
                index += 3;
                continue;
            }
            None if bytes[index] == b'+' => decoded.push(b' '),
            None => decoded.push(bytes[index]),
        }
        index += 1;
    }
    String::from_utf8_lossy(&decoded).into_owned()
}

/// A query integer as the daemon reads it: Python's `int()` of the text, and
/// `default` when that raises. Never `Err`; the `Result` keeps the callers'
/// shape. A value past `i64` saturates, which every caller clamps anyway.
pub(super) fn query_int(query: &str, key: &str, default: i64) -> Result<i64, ()> {
    let Some(value) = query_value(query, key)? else {
        return Ok(default);
    };
    Ok(python_int(&value).unwrap_or(default))
}

/// `int(text)` for a decimal string: surrounding whitespace, one sign, and
/// single underscores between digits.
pub(super) fn python_int(text: &str) -> Option<i64> {
    let trimmed = text.trim_matches(python_space);
    let (negative, digits) = match trimmed.chars().next()? {
        '-' => (true, &trimmed[1..]),
        '+' => (false, &trimmed[1..]),
        _ => (false, trimmed),
    };
    let mut magnitude = 0i128;
    let mut seen_digit = false;
    let mut last_underscore = false;
    for c in digits.chars() {
        if c == '_' {
            if !seen_digit || last_underscore {
                return None;
            }
            last_underscore = true;
            continue;
        }
        let value = decimal_value(c)?;
        seen_digit = true;
        last_underscore = false;
        magnitude = (magnitude * 10 + i128::from(value)).min(i128::from(i64::MAX) + 1);
    }
    if !seen_digit || last_underscore {
        return None;
    }
    let signed = if negative { -magnitude } else { magnitude };
    Some(signed.clamp(i128::from(i64::MIN), i128::from(i64::MAX)) as i64)
}

/// `str.isspace`, which `int()` strips: Unicode whitespace plus the ASCII
/// information separators U+001C..U+001F.
fn python_space(c: char) -> bool {
    c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c)
}

/// The value of a Unicode decimal digit (category Nd), as `int()` reads it.
fn decimal_value(c: char) -> Option<u32> {
    const ZEROS: [u32; 75] = [
        0x660, 0x6f0, 0x7c0, 0x966, 0x9e6, 0xa66, 0xae6, 0xb66, 0xbe6, 0xc66, 0xce6, 0xd66, 0xde6,
        0xe50, 0xed0, 0xf20, 0x1040, 0x1090, 0x17e0, 0x1810, 0x1946, 0x19d0, 0x1a80, 0x1a90,
        0x1b50, 0x1bb0, 0x1c40, 0x1c50, 0xa620, 0xa8d0, 0xa900, 0xa9d0, 0xa9f0, 0xaa50, 0xabf0,
        0xff10, 0x104a0, 0x10d30, 0x10d40, 0x11066, 0x110f0, 0x11136, 0x111d0, 0x112f0, 0x11450,
        0x114d0, 0x11650, 0x116c0, 0x116d0, 0x116da, 0x11730, 0x118e0, 0x11950, 0x11bf0, 0x11c50,
        0x11d50, 0x11da0, 0x11f50, 0x16130, 0x16a60, 0x16ac0, 0x16b50, 0x16d70, 0x1ccf0, 0x1d7ce,
        0x1d7d8, 0x1d7e2, 0x1d7ec, 0x1d7f6, 0x1e140, 0x1e2f0, 0x1e4f0, 0x1e5f1, 0x1e950, 0x1fbf0,
    ];
    if let Some(value) = c.to_digit(10) {
        return Some(value);
    }
    let code = u32::from(c);
    ZEROS
        .iter()
        .find(|zero| (**zero..**zero + 10).contains(&code))
        .map(|zero| code - zero)
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

/// The head waiting on `client` when its body has not all arrived: what a
/// handler that refuses on the head alone reads before the body.
pub(super) fn waiting_head(client: &TcpStream) -> Option<Vec<u8>> {
    let mut buffer = vec![0u8; MAX_HEAD_BYTES];
    let _ = client.set_nonblocking(true);
    let peeked = client.peek(&mut buffer);
    let _ = client.set_nonblocking(false);
    let head_len = head_end(&buffer[..peeked.ok()?])?;
    buffer.truncate(head_len);
    Some(buffer)
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
