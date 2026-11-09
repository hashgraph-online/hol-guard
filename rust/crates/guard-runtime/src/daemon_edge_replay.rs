//! Requests no native route answers, run through the daemon's own handler in
//! a short-lived Guard CLI process (`desktop daemon-replay`): the request's
//! raw bytes go to its standard input and its standard output is the raw
//! response, written back to the client unchanged. The handler applies every
//! origin, auth and body check it always has.

use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpStream};
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use super::reads::ReadConfig;
use crate::onefile_open_paths::{isolate_group, kill_group};

/// How long one replayed request may take before the client gets a 504.
const REPLAY_TIMEOUT: Duration = Duration::from_secs(120);
/// How long the client has to send the rest of its request.
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(10);
/// The handler refuses bodies past 1,000,000 bytes; past this the edge sends
/// the head alone and lets it say so.
const MAX_REPLAYED_BODY_BYTES: usize = 1_000_000;
const MAX_REPLAYED_HEAD_BYTES: usize = 64 * 1024;
/// The largest response a replay may print (an evidence export included).
const MAX_RESPONSE_BYTES: u64 = 64 * 1024 * 1024;

const UNAVAILABLE: &[u8] = b"HTTP/1.0 503 Service Unavailable\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: 38\r\nConnection: close\r\n\r\n{\"error\": \"daemon_route_unavailable\"}\n";

/// Answers the request on `client` through the CLI. `read_ahead` is the
/// request the edge already took off the socket, or empty when it took
/// nothing.
pub(in crate::daemon_edge) fn replay(
    client: &TcpStream,
    config: &ReadConfig,
    read_ahead: Vec<u8>,
    stalled_write: Duration,
    daemon_pid: u32,
) {
    let request = if read_ahead.is_empty() {
        read_request(client, REQUEST_READ_TIMEOUT)
    } else {
        Some(read_ahead)
    };
    let Some(request) = request else {
        let _ = client.shutdown(Shutdown::Both);
        return;
    };
    replay_with(client, config, request, stalled_write, daemon_pid, false);
}

/// Answers `request`, already read off `client`, through the CLI.
/// `proof_verified` tells the handler the edge checked the daemon identity
/// proof this hook presents on its connection.
pub(in crate::daemon_edge) fn replay_with(
    client: &TcpStream,
    config: &ReadConfig,
    request: Vec<u8>,
    stalled_write: Duration,
    daemon_pid: u32,
    proof_verified: bool,
) {
    let response = client
        .local_addr()
        .ok()
        .and_then(|local| run(config, local.port(), daemon_pid, proof_verified, request))
        .filter(|response| !response.is_empty());
    let _ = client.set_write_timeout(Some(stalled_write));
    let mut writer = client;
    let _ = writer.write_all(response.as_deref().unwrap_or(UNAVAILABLE));
    let _ = client.shutdown(Shutdown::Both);
}

/// One request's head and declared body, read straight off the socket
/// within `timeout`.
pub(in crate::daemon_edge) fn read_request(
    client: &TcpStream,
    timeout: Duration,
) -> Option<Vec<u8>> {
    let deadline = Instant::now() + timeout;
    let mut bytes = Vec::new();
    let mut chunk = [0u8; 8192];
    let head_len = loop {
        if let Some(end) = find_head_end(&bytes) {
            break end;
        }
        if bytes.len() >= MAX_REPLAYED_HEAD_BYTES {
            return None;
        }
        let read = read_some(client, &mut chunk, deadline)?;
        bytes.extend_from_slice(&chunk[..read]);
    };
    let declared = content_length(&bytes[..head_len]);
    let Some(length) = declared.filter(|length| *length <= MAX_REPLAYED_BODY_BYTES) else {
        // No body, or one the handler refuses by its declared length alone.
        bytes.truncate(head_len);
        return Some(bytes);
    };
    let total = head_len + length;
    while bytes.len() < total {
        let read = read_some(client, &mut chunk, deadline)?;
        bytes.extend_from_slice(&chunk[..read]);
    }
    bytes.truncate(total);
    Some(bytes)
}

fn read_some(client: &TcpStream, chunk: &mut [u8], deadline: Instant) -> Option<usize> {
    loop {
        let remaining = deadline.checked_duration_since(Instant::now())?;
        if remaining.is_zero() || client.set_read_timeout(Some(remaining)).is_err() {
            return None;
        }
        let mut reader = client;
        match reader.read(chunk) {
            Ok(0) => return None,
            Ok(read) => return Some(read),
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        }
    }
}

pub(in crate::daemon_edge) fn find_head_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|position| position + 4)
}

/// The one `Content-Length` the head declares; `None` for none, several, or
/// one that is not a number.
pub(in crate::daemon_edge) fn content_length(head: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(head).ok()?;
    let mut values = text.split("\r\n").skip(1).filter_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.trim()
            .eq_ignore_ascii_case("content-length")
            .then(|| value.trim())
    });
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.parse().ok()
}

/// The CLI's raw response to `request`, or `None` when the daemon named no
/// CLI or the CLI printed nothing in time.
fn run(
    config: &ReadConfig,
    port: u16,
    daemon_pid: u32,
    proof_verified: bool,
    request: Vec<u8>,
) -> Option<Vec<u8>> {
    let (argv, guard_home, cwd) = config.cli()?;
    let (program, prefix) = argv.split_first()?;
    let mut command = Command::new(program);
    command
        .args(prefix)
        .args(replay_args(guard_home, port, daemon_pid))
        .args(proof_verified.then_some("--daemon-proof-verified"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    if let Some(cwd) = cwd {
        command.current_dir(cwd);
    }
    isolate_group(&mut command);
    let mut child = command.spawn().ok()?;
    let (Some(mut stdin), Some(stdout)) = (child.stdin.take(), child.stdout.take()) else {
        stop(child);
        return None;
    };
    thread::spawn(move || {
        let _ = stdin.write_all(&request);
    });
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        let mut bytes = Vec::new();
        let read = stdout
            .take(MAX_RESPONSE_BYTES + 1)
            .read_to_end(&mut bytes)
            .is_ok();
        let _ = sender.send(read.then_some(bytes));
    });
    match receiver.recv_timeout(REPLAY_TIMEOUT) {
        Ok(Some(bytes)) if bytes.len() as u64 <= MAX_RESPONSE_BYTES => {
            // The handler may still be finishing work it started after
            // answering; the CLI bounds that itself.
            thread::spawn(move || {
                let _ = child.wait();
            });
            Some(bytes)
        }
        _ => {
            stop(child);
            None
        }
    }
}

/// The CLI arguments for one replay. `daemon_pid` is the process the
/// published daemon state names.
pub(in crate::daemon_edge) fn replay_args(
    guard_home: &str,
    port: u16,
    daemon_pid: u32,
) -> [String; 8] {
    [
        "desktop".to_owned(),
        "daemon-replay".to_owned(),
        "--guard-home".to_owned(),
        guard_home.to_owned(),
        "--port".to_owned(),
        port.to_string(),
        "--daemon-pid".to_owned(),
        daemon_pid.to_string(),
    ]
}

fn stop(mut child: Child) {
    kill_group(&child);
    let _ = child.kill();
    thread::spawn(move || {
        let _ = child.wait();
    });
}

#[cfg(all(test, unix))]
#[path = "daemon_edge_replay_tests.rs"]
mod tests;
