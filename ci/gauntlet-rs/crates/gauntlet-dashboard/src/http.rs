//! Minimal loopback HTTP surface: three embedded assets and two read-only APIs.

use crate::snapshot::PublicRoot;
use serde_json::json;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const MAX_HEADER: usize = 8192;
const CSP: &str = "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'";
const HTML: &[u8] = include_bytes!("../../../../gauntlet/control_plane/static/index.html");
const JS: &[u8] = include_bytes!("../../../../gauntlet/control_plane/static/app.js");
const CSS: &[u8] = include_bytes!("../../../../gauntlet/control_plane/static/style.css");

pub fn handle(mut stream: TcpStream, root: &PublicRoot) -> std::io::Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(3)))?;
    stream.set_write_timeout(Some(Duration::from_secs(3)))?;
    let mut request = Vec::new();
    let mut chunk = [0u8; 1024];
    while request.len() < MAX_HEADER && !request.windows(4).any(|part| part == b"\r\n\r\n") {
        let read = stream.read(&mut chunk)?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&chunk[..read]);
    }
    if request.len() > MAX_HEADER || !request.windows(4).any(|part| part == b"\r\n\r\n") {
        return reply(
            &mut stream,
            400,
            "Bad Request",
            "text/plain",
            b"Bad Request",
        );
    }
    let Ok(request) = std::str::from_utf8(&request) else {
        return reply(
            &mut stream,
            400,
            "Bad Request",
            "text/plain",
            b"Bad Request",
        );
    };
    let mut lines = request.split("\r\n");
    let Some(first) = lines.next() else {
        return reply(
            &mut stream,
            400,
            "Bad Request",
            "text/plain",
            b"Bad Request",
        );
    };
    let parts: Vec<&str> = first.split_whitespace().collect();
    if parts.len() != 3 || !matches!(parts[2], "HTTP/1.0" | "HTTP/1.1") {
        return reply(
            &mut stream,
            400,
            "Bad Request",
            "text/plain",
            b"Bad Request",
        );
    }
    let hosts: Vec<&str> = lines
        .filter_map(|line| line.split_once(':'))
        .filter(|(name, _)| name.eq_ignore_ascii_case("host"))
        .map(|(_, value)| value.trim())
        .collect();
    if hosts.len() != 1 || !allowed_host(hosts[0]) {
        return reply(&mut stream, 403, "Forbidden", "text/plain", b"Forbidden");
    }
    if parts[0] != "GET" {
        return reply(
            &mut stream,
            501,
            "Unsupported method",
            "text/plain",
            b"Unsupported method",
        );
    }
    let path = parts[1].split('?').next().unwrap_or("");
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs_f64();
    match path {
        "/" => reply(&mut stream, 200, "OK", "text/html; charset=utf-8", HTML),
        "/app.js" => reply(&mut stream, 200, "OK", "text/javascript", JS),
        "/style.css" => reply(&mut stream, 200, "OK", "text/css", CSS),
        "/api/status" => {
            let body = serde_json::to_vec(&root.snapshot(now))?;
            reply(&mut stream, 200, "OK", "application/json", &body)
        }
        "/healthz" => {
            let status = root.snapshot(now);
            let body = serde_json::to_vec(&json!({
                "service": "hol-gauntlet-dashboard",
                "instance_id": root.identity(),
                "server": "online",
                "collector": status["collector_status"]
            }))?;
            reply(&mut stream, 200, "OK", "application/json", &body)
        }
        _ => reply(&mut stream, 404, "Not Found", "text/plain", b"Not Found"),
    }
}

fn allowed_host(value: &str) -> bool {
    let (host, port) = value.split_once(':').unwrap_or((value, ""));
    matches!(host, "localhost" | "127.0.0.1")
        && (port.is_empty() || port.parse::<u16>().is_ok_and(|number| number > 0))
}

fn reply(
    stream: &mut TcpStream,
    code: u16,
    reason: &str,
    content_type: &str,
    body: &[u8],
) -> std::io::Result<()> {
    write!(
        stream,
        "HTTP/1.1 {code} {reason}\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nReferrer-Policy: no-referrer\r\nContent-Security-Policy: {CSP}\r\nConnection: close\r\n\r\n",
        body.len()
    )?;
    stream.write_all(body)
}
