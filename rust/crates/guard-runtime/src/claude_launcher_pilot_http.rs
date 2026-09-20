//! Bounded HTTP/1.x subset emitted by the existing Guard daemon.
//! One explicit TcpStream owns both requests; no pool, proxy, redirect or reconnect.
use serde_json::Value;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::Path;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use super::{auth, Failure, Result};

const HEADER_LIMIT: usize = 65_536;
const BODY_LIMIT: usize = 1_000_000;

pub(super) struct Connection {
    stream: TcpStream,
    deadline: Instant,
    host: String,
}

impl Connection {
    fn set_timeout(&self) -> Result<()> {
        prepare_io(&self.stream, self.deadline)
    }

    fn connect(state: &auth::State, deadline: Instant) -> Result<Self> {
        let host = auth::string(&state.value, "host")?;
        // Daemon discovery allows only these loopback identities. Avoid name
        // resolution, proxy environment and global DNS settings entirely.
        let address: IpAddr = if host.eq_ignore_ascii_case("localhost") {
            "127.0.0.1".parse().expect("literal loopback")
        } else {
            host.parse()
                .map_err(|_| Failure::identity("daemon URL must target loopback"))?
        };
        if !address.is_loopback() {
            return Err(Failure::identity("daemon URL must target loopback"));
        }
        let port = state.value["port"]
            .as_u64()
            .and_then(|value| u16::try_from(value).ok())
            .ok_or_else(|| Failure::identity("daemon state port is invalid"))?;
        let timeout = deadline
            .checked_duration_since(Instant::now())
            .ok_or_else(Failure::timeout)?;
        let stream = TcpStream::connect_timeout(&SocketAddr::new(address, port), timeout)
            .map_err(Failure::io)?;
        Ok(Self {
            stream,
            deadline,
            host: format!(
                "{}:{port}",
                if host.contains(':') {
                    format!("[{host}]")
                } else {
                    host.to_owned()
                }
            ),
        })
    }

    fn post(
        &mut self,
        path: &str,
        body: &[u8],
        proof: Option<(&str, &str)>,
    ) -> Result<(u16, String)> {
        if !path.starts_with('/') || path.bytes().any(|byte| !(0x21..=0x7e).contains(&byte)) {
            return Err(Failure::identity("claude_pilot_http_path_invalid"));
        }
        self.set_timeout()?;
        let connection = if proof.is_some() {
            "close"
        } else {
            "keep-alive"
        };
        let mut headers = format!("POST {path} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: {connection}\r\n", self.host, body.len());
        if let Some((nonce, signature)) = proof {
            headers.push_str(&format!(
                "X-Guard-Daemon-Nonce: {nonce}\r\nX-Guard-Daemon-Proof: {signature}\r\n"
            ));
        }
        headers.push_str("\r\n");
        let deadline = self.deadline;
        write_with_budget(&mut self.stream, headers.as_bytes(), |stream| {
            prepare_io(stream, deadline)
        })?;
        write_with_budget(&mut self.stream, body, |stream| {
            prepare_io(stream, deadline)
        })?;
        self.response(if proof.is_some() {
            "daemon hook"
        } else {
            "daemon identity challenge"
        })
    }

    fn response(&mut self, label: &str) -> Result<(u16, String)> {
        let mut header = Vec::new();
        while !header.ends_with(b"\r\n\r\n") {
            if header.len() >= HEADER_LIMIT {
                return Err(Failure::identity("daemon response headers are too large"));
            }
            self.set_timeout()?;
            let mut byte = [0; 1];
            self.stream.read_exact(&mut byte).map_err(Failure::io)?;
            header.push(byte[0]);
        }
        let header = String::from_utf8(header)
            .map_err(|_| Failure::identity("daemon HTTP headers are malformed"))?;
        let mut lines = header.split("\r\n");
        let status_line = lines.next().unwrap_or_default();
        let mut status_parts = status_line.splitn(3, ' ');
        if !matches!(status_parts.next(), Some("HTTP/1.0" | "HTTP/1.1")) {
            return Err(Failure::identity("daemon HTTP status is malformed"));
        }
        let status: u16 = status_parts
            .next()
            .and_then(|value| value.parse().ok())
            .filter(|value| (100..=599).contains(value))
            .ok_or_else(|| Failure::identity("daemon HTTP status is malformed"))?;
        let mut length = None;
        for line in lines.filter(|line| !line.is_empty()) {
            let (name, value) = line
                .split_once(':')
                .ok_or_else(|| Failure::identity("daemon HTTP headers are malformed"))?;
            if name.eq_ignore_ascii_case("transfer-encoding") {
                return Err(Failure::identity(
                    "daemon response uses unsupported transfer encoding",
                ));
            }
            if name.eq_ignore_ascii_case("content-length") {
                if length.is_some() {
                    return Err(Failure::identity("daemon response length is ambiguous"));
                }
                length = Some(
                    value
                        .trim()
                        .parse::<usize>()
                        .map_err(|_| Failure::identity("daemon response length is invalid"))?,
                );
            }
        }
        let length =
            length.ok_or_else(|| Failure::identity("daemon response has no explicit length"))?;
        let deadline = self.deadline;
        let body = read_body(&mut self.stream, length, label, |stream| {
            prepare_io(stream, deadline)
        })?;
        Ok((status, String::from_utf8_lossy(&body).into_owned()))
    }
}

fn prepare_io(stream: &TcpStream, deadline: Instant) -> Result<()> {
    let remaining = deadline
        .checked_duration_since(Instant::now())
        .filter(|value| *value >= Duration::from_millis(10))
        .ok_or_else(Failure::timeout)?;
    stream
        .set_read_timeout(Some(remaining))
        .map_err(Failure::io)?;
    stream
        .set_write_timeout(Some(remaining))
        .map_err(Failure::io)
}

fn write_with_budget<W: Write>(
    stream: &mut W,
    mut bytes: &[u8],
    mut prepare: impl FnMut(&W) -> Result<()>,
) -> Result<()> {
    while !bytes.is_empty() {
        prepare(stream)?;
        match stream.write(bytes) {
            Ok(0) => return Err(Failure::io(std::io::ErrorKind::WriteZero.into())),
            Ok(count) => bytes = &bytes[count..],
            Err(error) if error.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(error) => return Err(Failure::io(error)),
        }
    }
    Ok(())
}

fn read_body<R: Read>(
    stream: &mut R,
    declared_length: usize,
    label: &str,
    mut prepare: impl FnMut(&R) -> Result<()>,
) -> Result<Vec<u8>> {
    // Bound received bytes, as Python read1 does. A larger declared length
    // followed by early EOF is not itself an oversize actual body.
    let length = declared_length.min(BODY_LIMIT + 1);
    let mut body = vec![0; length];
    let mut offset = 0;
    while offset < length {
        prepare(stream)?;
        let end = (offset + 65_536).min(length);
        let count = stream.read(&mut body[offset..end]).map_err(Failure::io)?;
        if count == 0 {
            body.truncate(offset);
            return Ok(body);
        }
        offset += count;
    }
    if body.len() > BODY_LIMIT {
        return Err(Failure::identity(&format!("{label} response is too large")));
    }
    // HTTPResponse.read1() performs a final budget check before its local
    // length-zero/EOF result, even when the last body chunk was complete.
    // A real early EOF above already made that checked read and must not
    // acquire an extra completion gate. Terminal output remains unchanged.
    prepare(stream)?;
    Ok(body)
}

#[cfg(test)]
#[path = "claude_launcher_pilot_http_tests.rs"]
mod tests;

pub(super) fn request(
    state: &auth::State,
    state_path: &Path,
    query: &str,
    data: &str,
    event: &str,
    deadline: Instant,
) -> Result<String> {
    let mut connection = Connection::connect(state, deadline)?;
    let mut random = [0; 32];
    getrandom::fill(&mut random)
        .map_err(|_| Failure::identity("daemon identity nonce generation failed"))?;
    let nonce = hex::encode(random);
    let challenge = serde_json::json!({"protocol_version": 1, "nonce": nonce, "state_id": state.value["state_id"], "hook_event": event});
    let (status, response) = connection.post(
        "/v1/daemon/identity-challenge",
        challenge.to_string().as_bytes(),
        None,
    )?;
    if status != 200 {
        return Err(Failure::http(status, &response));
    }
    let response: Value = serde_json::from_str(&response)
        .map_err(|_| Failure::identity("daemon identity challenge returned malformed JSON"))?;
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Failure::identity("daemon identity clock is unavailable"))?
        .as_millis();
    let proof = auth::challenge_proof(
        &response,
        state,
        &nonce,
        event,
        u64::try_from(now_ms).unwrap_or(u64::MAX),
    )?;
    let current = auth::load_state(state_path).map_err(|mut failure| {
        failure.value["kind"] = Value::String("identity".into());
        failure
    })?;
    if !auth::same_generation(state, &current) {
        return Err(Failure::identity(
            "daemon state changed during identity verification",
        ));
    }
    let (status, response) = connection.post(
        &format!("/v1/hooks/claude-code?{query}"),
        data.as_bytes(),
        Some((&nonce, &proof)),
    )?;
    if status != 200 {
        return Err(Failure::http(status, &response));
    }
    Ok(response)
}
