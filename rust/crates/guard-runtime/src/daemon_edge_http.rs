//! The narrow slice of HTTP the daemon edge reads before it relays.
//!
//! The edge answers a request itself only when this module reads it the same
//! way the daemon's Python server would. Anything it cannot read exactly, such
//! as a percent-encoded path, a folded header or a request body, makes the
//! parser give up, and the edge then relays the untouched bytes to the daemon.

/// A request head the edge can answer: a plain `GET` with no body.
#[derive(Debug, PartialEq, Eq)]
pub(super) struct GetRequest<'a> {
    pub(super) path: &'a str,
    pub(super) query: &'a str,
    headers: Vec<(&'a str, &'a str)>,
}

impl<'a> GetRequest<'a> {
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
pub(super) fn parse_get(head: &[u8]) -> Option<GetRequest<'_>> {
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
        || method != "GET"
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
    Some(GetRequest {
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
