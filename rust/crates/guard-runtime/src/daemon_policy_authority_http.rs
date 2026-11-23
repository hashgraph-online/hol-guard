use super::*;

// ---------------------------------------------------------------------------
// Loopback HTTP — `GuardSurfaceDaemonClient._post` parity
// (client.py:434-:455). Plain HTTP to 127.0.0.1 only; the daemon token is
// never sent elsewhere. `Connection: close` lets us bound the body read.
// ---------------------------------------------------------------------------

pub(crate) fn http_get_json(url: &str, headers: &[(&str, &str)]) -> Option<Value> {
    let (host, port, path) = parse_loopback_url(url)?;
    let response = http_request("GET", &host, port, &path, headers, None, HEALTH_TIMEOUT)?;
    serde_json::from_slice(&response).ok()
}
/// One JSON request to a loopback daemon port within `timeout`; `None` on
/// any transport failure, non-2xx status or non-object body.
pub(crate) fn loopback_json(
    method: &str,
    port: u16,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&Value>,
    timeout: Duration,
) -> Option<Map<String, Value>> {
    if timeout.is_zero() {
        return None;
    }
    let bytes = body.map(serde_json::to_vec).transpose().ok()?;
    let response = http_request(
        method,
        "127.0.0.1",
        port,
        path,
        headers,
        bytes.as_deref(),
        timeout,
    )?;
    match serde_json::from_slice(&response).ok()? {
        Value::Object(map) => Some(map),
        _ => None,
    }
}

pub(crate) fn post_json(authority: &DaemonAuthority, path: &str, payload: &Value) -> Option<Value> {
    let body = serde_json::to_vec(payload).ok()?;
    let (host, port, _ignored) = parse_loopback_url(&authority.base_url)?;
    let headers = [
        ("Content-Type", "application/json"),
        ("X-Guard-Token", authority.auth_token.as_str()),
    ];
    let response = http_request(
        "POST",
        &host,
        port,
        path,
        &headers,
        Some(&body),
        POLICY_TIMEOUT,
    )?;
    serde_json::from_slice(&response).ok()
}

/// Loopback-only URL parse (client.py:416-:426). Rejects any non-
/// `127.0.0.1` host, credentials, query, or fragment.
fn parse_loopback_url(url: &str) -> Option<(String, u16, String)> {
    let rest = url.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(idx) => (&rest[..idx], &rest[idx..]),
        None => (rest, "/"),
    };
    if authority.contains('@') || path.contains('?') || path.contains('#') {
        return None;
    }
    let (host, port_raw) = authority.rsplit_once(':')?;
    if host != "127.0.0.1" {
        return None;
    }
    let port = port_raw.parse::<u16>().ok()?;
    Some(("127.0.0.1".to_owned(), port, path.to_owned()))
}

fn http_request(
    method: &str,
    host: &str,
    port: u16,
    path: &str,
    headers: &[(&str, &str)],
    body: Option<&[u8]>,
    timeout: Duration,
) -> Option<Vec<u8>> {
    use std::net::ToSocketAddrs;
    let addr = (host, port).to_socket_addrs().ok()?.next()?;
    let mut stream = TcpStream::connect_timeout(&addr, timeout).ok()?;
    stream.set_read_timeout(Some(timeout)).ok()?;
    stream.set_write_timeout(Some(timeout)).ok()?;
    let mut request =
        format!("{method} {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n");
    for (name, value) in headers {
        request.push_str(&format!("{name}: {value}\r\n"));
    }
    if let Some(body) = body {
        request.push_str(&format!("Content-Length: {}\r\n", body.len()));
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).ok()?;
    if let Some(body) = body {
        stream.write_all(body).ok()?;
    }
    let mut response = Vec::new();
    {
        let mut limited = stream
            .try_clone()
            .ok()?
            .take((DAEMON_RESPONSE_MAX_BYTES + 1) as u64);
        limited.read_to_end(&mut response).ok()?;
    }
    let _ = stream.shutdown(Shutdown::Both);
    parse_http_response(&response)
}

/// Minimal HTTP/1.1 response parser: status line + headers + body. The
/// daemon sends `Content-Length` (server.py:8571); `Connection: close`
/// bounds the read. Chunked bodies are rejected, and so is a body shorter
/// than its `Content-Length` (a truncated read).
fn parse_http_response(raw: &[u8]) -> Option<Vec<u8>> {
    let header_end = raw.windows(4).position(|w| w == b"\r\n\r\n")?;
    let header_text = std::str::from_utf8(&raw[..header_end]).ok()?;
    let body = &raw[header_end + 4..];
    let mut lines = header_text.split("\r\n");
    let status_line = lines.next()?;
    let mut parts = status_line.split_whitespace();
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    let status: u16 = parts.next()?.parse().ok()?;
    let mut content_length: Option<usize> = None;
    for line in lines {
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        if name.trim().eq_ignore_ascii_case("content-length") {
            content_length = value.trim().parse().ok();
        }
    }
    if !(200..300).contains(&status) {
        return None;
    }
    match content_length {
        Some(len) => Some(body.get(..len)?.to_vec()),
        None => Some(body.to_vec()),
    }
}

#[cfg(test)]
mod tests {
    use super::parse_http_response;

    #[test]
    fn truncated_body_shorter_than_content_length_is_rejected() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 10\r\n\r\n{\"a\":1";
        assert_eq!(parse_http_response(raw), None);
    }

    #[test]
    fn body_is_cut_at_content_length() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\n{\"a\":1}trailing";
        assert_eq!(parse_http_response(raw), Some(b"{\"a\":1}".to_vec()));
    }
}
