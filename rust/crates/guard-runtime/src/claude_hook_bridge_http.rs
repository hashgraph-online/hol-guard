//! The loopback HTTP/1.1 client behind the native Claude hook bridge. It
//! mirrors what the Python transport gets from `http.client.HTTPConnection`:
//! one keep-alive connection that carries the identity challenge and then
//! the hook, Content-Length or close-delimited bodies, and CPython's error
//! text, since the bridge writes that text into the hook reason. Every
//! socket operation is bounded by the hook deadline.

use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

use crate::claude_hook_bridge_http_text::{latin1, py_int, py_isspace, validate_request_target};
use crate::claude_hook_bridge_transport::BridgeError;

pub(crate) const MAX_DAEMON_RESPONSE_BYTES: usize = 1_000_000;
pub(crate) const MINIMUM_OPERATION: Duration = Duration::from_millis(10);
const MAX_LINE: usize = 65_536;
const MAX_HEADERS: usize = 100;
const READ_CHUNK: usize = 64 * 1024;

pub(crate) fn remaining(deadline: Instant) -> Duration {
    deadline.saturating_duration_since(Instant::now())
}

/// `str(OSError)`: `[Errno N] message`, or `timed out` for a socket timeout.
pub(crate) fn os_error(error: &io::Error) -> String {
    if matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    ) {
        return "timed out".to_owned();
    }
    let text = error.to_string();
    match error.raw_os_error() {
        Some(code) => {
            let suffix = format!(" (os error {code})");
            format!(
                "[Errno {code}] {}",
                text.strip_suffix(&suffix).unwrap_or(&text)
            )
        }
        None => text,
    }
}

fn transport(error: &io::Error) -> BridgeError {
    BridgeError::Transport(os_error(error))
}

fn is_timeout(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    )
}

/// The socket timeout for the next operation: what is left of the deadline.
fn operation_timeout(deadline: Instant) -> Result<Duration, BridgeError> {
    let left = remaining(deadline);
    if left.is_zero() {
        return Err(BridgeError::Transport("timed out".to_owned()));
    }
    Ok(left)
}

/// One parsed response head: the status and how its body is framed.
#[derive(Debug)]
pub(crate) struct ResponseHead {
    pub(crate) status: u16,
    length: Option<usize>,
    will_close: bool,
}

/// A keep-alive loopback connection, opened on first use and reopened when
/// the daemon closed the previous exchange, like `HTTPConnection.auto_open`.
pub(crate) struct LoopbackConnection {
    host: String,
    port: u16,
    stream: Option<BufReader<TcpStream>>,
}

impl LoopbackConnection {
    pub(crate) fn new(host: &str, port: u16) -> Self {
        LoopbackConnection {
            host: host.to_owned(),
            port,
            stream: None,
        }
    }

    fn host_header(&self) -> String {
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        if self.port == 80 {
            host
        } else {
            format!("{host}:{}", self.port)
        }
    }

    fn connect(&self, deadline: Instant) -> Result<TcpStream, BridgeError> {
        let addresses = (self.host.as_str(), self.port)
            .to_socket_addrs()
            .map_err(|error| {
                let text = error.to_string();
                BridgeError::Transport(
                    text.strip_prefix("failed to lookup address information: ")
                        .unwrap_or(&text)
                        .to_owned(),
                )
            })?;
        let mut last_error = None;
        // The daemon state names a loopback host; never follow a resolver
        // that maps it anywhere else.
        for address in addresses.filter(|address| address.ip().is_loopback()) {
            let timeout = operation_timeout(deadline)?;
            match TcpStream::connect_timeout(&address, timeout) {
                Ok(stream) => {
                    stream
                        .set_nodelay(true)
                        .map_err(|error| transport(&error))?;
                    return Ok(stream);
                }
                Err(error) => last_error = Some(error),
            }
        }
        Err(match last_error {
            Some(error) => transport(&error),
            None => BridgeError::Transport("getaddrinfo returns an empty list".to_owned()),
        })
    }

    /// `connection.request("POST", url, body=..., headers=...)` followed by
    /// `getresponse()`: sends the request and reads the response head.
    pub(crate) fn post(
        &mut self,
        url: &str,
        headers: &[(&str, &str)],
        body: &[u8],
        deadline: Instant,
    ) -> Result<ResponseHead, BridgeError> {
        self.send("POST", url, headers, Some(body), deadline)
    }

    /// `connection.request("GET", url, headers=...)` followed by
    /// `getresponse()`: a bodyless request, sent without a Content-Length.
    pub(crate) fn get(
        &mut self,
        url: &str,
        headers: &[(&str, &str)],
        deadline: Instant,
    ) -> Result<ResponseHead, BridgeError> {
        self.send("GET", url, headers, None, deadline)
    }

    fn send(
        &mut self,
        method: &str,
        url: &str,
        headers: &[(&str, &str)],
        body: Option<&[u8]>,
        deadline: Instant,
    ) -> Result<ResponseHead, BridgeError> {
        validate_request_target(url)?;
        let mut message = format!(
            "{method} {url} HTTP/1.1\r\nHost: {}\r\nAccept-Encoding: identity\r\n",
            self.host_header(),
        );
        if let Some(body) = body {
            message.push_str(&format!("Content-Length: {}\r\n", body.len()));
        }
        for (name, value) in headers {
            message.push_str(&format!("{name}: {value}\r\n"));
        }
        message.push_str("\r\n");
        let mut message = message.into_bytes();
        message.extend_from_slice(body.unwrap_or_default());
        if self.stream.is_none() {
            self.stream = Some(BufReader::new(self.connect(deadline)?));
        }
        let result = self.exchange(&message, deadline);
        if result.is_err() {
            self.stream = None;
        }
        result
    }

    fn exchange(&mut self, message: &[u8], deadline: Instant) -> Result<ResponseHead, BridgeError> {
        let reader = self
            .stream
            .as_mut()
            .ok_or_else(|| BridgeError::Transport("not connected".to_owned()))?;
        let timeout = operation_timeout(deadline)?;
        let stream = reader.get_mut();
        stream
            .set_write_timeout(Some(timeout))
            .map_err(|error| transport(&error))?;
        stream
            .write_all(message)
            .map_err(|error| transport(&error))?;
        read_head(reader, deadline)
    }

    /// The `read1` loop both Python readers share: a deadline check before
    /// every read, at most 64 KiB per read, and one byte past the limit so
    /// the caller can refuse an oversized body. `deadline_message` is the
    /// `TimeoutError` raised when too little time is left to read, and
    /// `timeout_message` the one a socket timeout surfaces as.
    pub(crate) fn read_body(
        &mut self,
        head: &ResponseHead,
        deadline: Instant,
        deadline_message: &str,
        timeout_message: &str,
    ) -> Result<Vec<u8>, BridgeError> {
        let mut body = Vec::new();
        let mut left = head.length;
        let mut chunk = vec![0_u8; READ_CHUNK];
        let mut clean = false;
        while body.len() <= MAX_DAEMON_RESPONSE_BYTES {
            let available = remaining(deadline);
            if available < MINIMUM_OPERATION {
                self.stream = None;
                return Err(BridgeError::Transport(deadline_message.to_owned()));
            }
            let want = READ_CHUNK
                .min(MAX_DAEMON_RESPONSE_BYTES + 1 - body.len())
                .min(left.unwrap_or(usize::MAX));
            let Some(reader) = self.stream.as_mut().filter(|_| want > 0) else {
                clean = left == Some(0);
                break;
            };
            if let Err(error) = reader.get_ref().set_read_timeout(Some(available)) {
                self.stream = None;
                return Err(transport(&error));
            }
            match reader.read(&mut chunk[..want]) {
                Ok(0) => break,
                Ok(count) => {
                    body.extend_from_slice(&chunk[..count]);
                    if let Some(left) = left.as_mut() {
                        *left -= count;
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
                Err(error) => {
                    self.stream = None;
                    return Err(if is_timeout(&error) {
                        BridgeError::Transport(timeout_message.to_owned())
                    } else {
                        transport(&error)
                    });
                }
            }
        }
        if head.will_close || !clean {
            self.stream = None;
        }
        Ok(body)
    }
}

/// `fp.readline(65537)`, with the read timeout reset to what is left.
fn read_line(reader: &mut BufReader<TcpStream>, deadline: Instant) -> Result<Vec<u8>, BridgeError> {
    let mut line = Vec::new();
    while line.len() <= MAX_LINE {
        let timeout = operation_timeout(deadline)?;
        reader
            .get_ref()
            .set_read_timeout(Some(timeout))
            .map_err(|error| transport(&error))?;
        let available = match reader.fill_buf() {
            Ok(available) => available,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(transport(&error)),
        };
        if available.is_empty() {
            break;
        }
        let limit = available.len().min(MAX_LINE + 1 - line.len());
        let (taken, complete) = match available[..limit].iter().position(|byte| *byte == b'\n') {
            Some(index) => (index + 1, true),
            None => (limit, false),
        };
        line.extend_from_slice(&available[..taken]);
        reader.consume(taken);
        if complete {
            break;
        }
    }
    Ok(line)
}

/// `http.client._read_headers`: raw header lines up to the blank line.
fn read_header_lines(
    reader: &mut BufReader<TcpStream>,
    deadline: Instant,
) -> Result<Vec<Vec<u8>>, BridgeError> {
    let mut lines = Vec::new();
    loop {
        let line = read_line(reader, deadline)?;
        if line.len() > MAX_LINE {
            return Err(BridgeError::Transport(format!(
                "got more than {MAX_LINE} bytes when reading header line"
            )));
        }
        if lines.len() > MAX_HEADERS {
            return Err(BridgeError::Transport(format!(
                "got more than {MAX_HEADERS} headers"
            )));
        }
        if matches!(line.as_slice(), b"\r\n" | b"\n" | b"") {
            return Ok(lines);
        }
        lines.push(line);
    }
}

/// `HTTPResponse._read_status`: the protocol version and status code.
fn read_status(
    reader: &mut BufReader<TcpStream>,
    deadline: Instant,
) -> Result<(String, u16), BridgeError> {
    let line = read_line(reader, deadline)?;
    if line.len() > MAX_LINE {
        return Err(BridgeError::Transport(format!(
            "got more than {MAX_LINE} bytes when reading status line"
        )));
    }
    if line.is_empty() {
        return Err(BridgeError::Transport(
            "Remote end closed connection without response".to_owned(),
        ));
    }
    let text = latin1(&line);
    let bad_status = || BridgeError::Transport(text.clone());
    let mut tokens = text.split(py_isspace).filter(|token| !token.is_empty());
    let (Some(version), Some(status)) = (tokens.next(), tokens.next()) else {
        return Err(bad_status());
    };
    if !version.starts_with("HTTP/") {
        return Err(bad_status());
    }
    let status = py_int(status)
        .filter(|status| (100..=999).contains(status))
        .ok_or_else(bad_status)?;
    Ok((version.to_owned(), status as u16))
}

/// The `email.feedparser` header block of `http.client.parse_headers` under
/// the compat32 policy: physical lines split at `\r\n`, `\r` or `\n`, ended
/// by the first line that is neither a header nor a continuation.
pub(crate) fn parse_header_block(lines: &[Vec<u8>]) -> Vec<(String, String)> {
    let text = latin1(&lines.concat());
    let mut physical = Vec::new();
    let mut start = 0;
    let bytes = text.as_bytes();
    let mut index = 0;
    while index < bytes.len() {
        let end = match bytes[index] {
            b'\r' if bytes.get(index + 1) == Some(&b'\n') => index + 2,
            b'\r' | b'\n' => index + 1,
            _ => {
                index += 1;
                continue;
            }
        };
        physical.push(&text[start..end]);
        start = end;
        index = end;
    }
    if start < text.len() {
        physical.push(&text[start..]);
    }
    let mut headers = Vec::new();
    let mut current: Option<(String, String)> = None;
    let finish =
        |(name, value): (String, String)| (name, value.trim_end_matches(['\r', '\n']).to_owned());
    for line in physical {
        if !is_header_line(line) {
            break;
        }
        if line.starts_with([' ', '\t']) {
            if let Some((_, value)) = current.as_mut() {
                value.push_str(line);
            }
            continue;
        }
        if let Some(header) = current.take() {
            headers.push(finish(header));
        }
        if line.starts_with("From ") {
            continue;
        }
        match line.find(':') {
            Some(colon) if colon > 0 => {
                let value = line[colon + 1..].trim_start_matches([' ', '\t']);
                current = Some((line[..colon].to_owned(), value.to_owned()));
            }
            _ => {}
        }
    }
    if let Some(header) = current {
        headers.push(finish(header));
    }
    headers
}

/// `email.feedparser.headerRE`: `^(From |[\041-\071\073-\176]*:|[\t ])`.
fn is_header_line(line: &str) -> bool {
    if line.starts_with("From ") || line.starts_with([' ', '\t']) {
        return true;
    }
    let name_end = line
        .find(|c: char| !matches!(c, '\u{21}'..='\u{39}' | '\u{3b}'..='\u{7e}'))
        .unwrap_or(line.len());
    line[name_end..].starts_with(':')
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(existing, _)| existing.to_lowercase() == name)
        .map(|(_, value)| value.as_str())
}

/// `HTTPResponse.begin`: status, headers and body framing.
fn read_head(
    reader: &mut BufReader<TcpStream>,
    deadline: Instant,
) -> Result<ResponseHead, BridgeError> {
    let (version, status) = loop {
        let (version, status) = read_status(reader, deadline)?;
        if status != 100 {
            break (version, status);
        }
        read_header_lines(reader, deadline)?;
    };
    let http11 = match version.as_str() {
        "HTTP/1.0" | "HTTP/0.9" => false,
        other if other.starts_with("HTTP/1.") => true,
        other => return Err(BridgeError::Transport(other.to_owned())),
    };
    let headers = parse_header_block(&read_header_lines(reader, deadline)?);
    frame_response(status, http11, &headers)
}

pub(crate) fn frame_response(
    status: u16,
    http11: bool,
    headers: &[(String, String)],
) -> Result<ResponseHead, BridgeError> {
    if header(headers, "transfer-encoding").is_some_and(|value| value.to_lowercase() == "chunked") {
        // The daemon always frames with Content-Length; refuse the rest.
        return Err(BridgeError::Transport(
            "chunked daemon responses are not supported".to_owned(),
        ));
    }
    let has = |name: &str, token: &str| {
        header(headers, name).is_some_and(|value| value.to_lowercase().contains(token))
    };
    let mut will_close = if http11 {
        has("connection", "close")
    } else {
        !(header(headers, "keep-alive").is_some_and(|value| !value.is_empty())
            || has("connection", "keep-alive")
            || has("proxy-connection", "keep-alive"))
    };
    let mut length = header(headers, "content-length")
        .filter(|value| !value.is_empty())
        .and_then(py_int)
        .and_then(|length| usize::try_from(length).ok());
    if status == 204 || status == 304 || (100..200).contains(&status) {
        length = Some(0);
    }
    if length.is_none() {
        will_close = true;
    }
    Ok(ResponseHead {
        status,
        length,
        will_close,
    })
}

#[cfg(all(test, unix))]
#[path = "claude_hook_bridge_http_tests.rs"]
mod tests;
