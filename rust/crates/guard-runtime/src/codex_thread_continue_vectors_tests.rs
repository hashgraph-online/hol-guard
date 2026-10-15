//! Replays the recorded Python continuation vectors against the resident op.
//!
//! Each vector scripts a fake Codex app-server on a private Unix socket. The
//! op must return the recorded result, and the server must receive the same
//! JSON-RPC messages (and pongs) the Python client sent.

use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::Duration;

use base64ct::{Base64, Encoding};
use serde_json::{json, Map, Value};
use sha1::{Digest, Sha1};

use super::{continue_thread, ContinueRequest};

const VECTORS: &str =
    include_str!("../testdata/codex_app_server/codex_thread_continue_vectors.json");
const GUID: &str = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

#[test]
fn codex_thread_continue_matches_recorded_python_vectors() {
    let document: Value = serde_json::from_str(VECTORS).expect("vectors parse");
    let timeout_ms = (document["timeout_seconds"].as_f64().expect("timeout") * 1000.0) as u64;
    let request_id = document["request_id"]
        .as_str()
        .expect("request id")
        .to_owned();
    let vectors = document["vectors"].as_array().expect("vectors").clone();
    assert!(vectors.len() >= 40, "expected the full recorded set");
    let handles: Vec<_> = vectors
        .into_iter()
        .enumerate()
        .map(|(index, vector)| {
            let request_id = request_id.clone();
            thread::spawn(move || run_vector(index, &vector, &request_id, timeout_ms))
        })
        .collect();
    let failures: Vec<String> = handles
        .into_iter()
        .filter_map(|handle| handle.join().expect("vector thread").err())
        .collect();
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

fn run_vector(
    index: usize,
    vector: &Value,
    request_id: &str,
    timeout_ms: u64,
) -> Result<(), String> {
    let name = vector["name"].as_str().unwrap_or("?").to_owned();
    let base = PathBuf::from(format!("/tmp/cxr{}-{index}", std::process::id()));
    let _ = fs::remove_dir_all(&base);
    fs::create_dir(&base).map_err(|error| format!("{name}: {error}"))?;
    fs::set_permissions(&base, fs::Permissions::from_mode(0o700)).expect("chmod base");
    let outcome = replay(vector, request_id, timeout_ms, &base);
    let _ = fs::remove_dir_all(&base);
    let (result, server) = outcome;
    let expected = &vector["expected"];
    if expected["result"] != result {
        return Err(format!(
            "{name}: result {result} != recorded {}",
            expected["result"]
        ));
    }
    if expected["server"] != server {
        return Err(format!(
            "{name}: server saw {server} != recorded {}",
            expected["server"]
        ));
    }
    Ok(())
}

fn replay(vector: &Value, request_id: &str, timeout_ms: u64, base: &Path) -> (Value, Value) {
    let mode = vector["socket"].as_str().unwrap_or("server");
    let mut socket_path = base.join("s.sock");
    if mode == "codex_home" {
        let control = base.join("codex-home").join("app-server-control");
        fs::create_dir_all(&control).expect("codex home");
        fs::set_permissions(&control, fs::Permissions::from_mode(0o700)).expect("chmod control");
        socket_path = control.join("app-server-control.sock");
    }
    let socket_text = socket_path.to_str().expect("utf-8 path").to_owned();
    let base_text = base.to_str().expect("utf-8 path").to_owned();
    let metadata = substitute(&vector["metadata"], &socket_text, &base_text);
    let stop = Arc::new(AtomicBool::new(false));
    let mut listener_guard: Option<UnixListener> = None;
    let mut server = None;
    match mode {
        "server" | "codex_home" => {
            let listener = UnixListener::bind(&socket_path).expect("bind");
            let connections = vector["connections"]
                .as_array()
                .cloned()
                .unwrap_or_default();
            let stop = Arc::clone(&stop);
            server = Some(thread::spawn(move || serve(&listener, &connections, &stop)));
        }
        "stale" => drop(UnixListener::bind(&socket_path).expect("bind")),
        "loose_parent" => {
            listener_guard = Some(UnixListener::bind(&socket_path).expect("bind"));
            fs::set_permissions(base, fs::Permissions::from_mode(0o770)).expect("chmod loose");
        }
        "regular_file" => fs::write(&socket_path, b"").expect("regular file"),
        _ => {}
    }
    let temp_dir = std::env::temp_dir();
    let request = ContinueRequest {
        approval_request_id: request_id,
        action: vector["action"].as_str().unwrap_or("allow"),
        home_dir: Some("/nonexistent-codex-vector-home"),
        temp_dir: temp_dir.to_str(),
        cwd: Some(&base_text),
        timeout_ms,
    };
    let result = match &metadata {
        Value::Object(map) => continue_thread(&request, map),
        _ => Value::Null,
    };
    stop.store(true, Ordering::SeqCst);
    drop(listener_guard);
    let records = server
        .map(|handle| handle.join().expect("server thread"))
        .unwrap_or_default();
    (result, Value::Array(records))
}

fn substitute(value: &Value, socket: &str, directory: &str) -> Value {
    match value {
        Value::String(text) => Value::String(
            text.replace("${SOCKET}", socket)
                .replace("${SOCKET_DIR}", directory),
        ),
        Value::Object(map) => Value::Object(
            map.iter()
                .map(|(key, item)| (key.clone(), substitute(item, socket, directory)))
                .collect(),
        ),
        other => other.clone(),
    }
}

fn serve(listener: &UnixListener, connections: &[Value], stop: &AtomicBool) -> Vec<Value> {
    listener
        .set_nonblocking(true)
        .expect("nonblocking listener");
    let mut records = Vec::new();
    for script in connections {
        let stream = loop {
            match listener.accept() {
                Ok((stream, _)) => break Some(stream),
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    if stop.load(Ordering::SeqCst) {
                        break None;
                    }
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break None,
            }
        };
        let Some(mut stream) = stream else {
            break;
        };
        stream.set_nonblocking(false).expect("blocking stream");
        let mut record = Map::new();
        let _ = serve_connection(&mut stream, script, &mut record);
        records.push(Value::Object(record));
    }
    records
}

fn serve_connection(
    stream: &mut UnixStream,
    script: &Value,
    record: &mut Map<String, Value>,
) -> std::io::Result<()> {
    let mut request = Vec::new();
    while !request.windows(4).any(|window| window == b"\r\n\r\n") {
        let mut chunk = [0_u8; 4096];
        let count = stream.read(&mut chunk)?;
        if count == 0 {
            return Ok(());
        }
        request.extend_from_slice(&chunk[..count]);
    }
    let handshake = script["handshake"].as_str().unwrap_or("ok");
    if handshake == "eof" {
        return Ok(());
    }
    let text = String::from_utf8_lossy(&request).into_owned();
    let key = text
        .split("\r\n")
        .skip(1)
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            (name.to_lowercase() == "sec-websocket-key").then(|| value.trim().to_owned())
        })
        .unwrap_or_default();
    if handshake == "bad_status" {
        stream.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n")?;
        return Ok(());
    }
    let mut digest = Sha1::new();
    digest.update(key.as_bytes());
    digest.update(GUID.as_bytes());
    let mut accept = Base64::encode_string(&digest.finalize());
    if handshake == "bad_accept" {
        accept = Base64::encode_string(b"wrongwrongwrongwrong");
    }
    stream.write_all(
        format!(
            "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {accept}\r\n\r\n"
        )
        .as_bytes(),
    )?;
    if handshake == "bad_accept" {
        return Ok(());
    }
    record.insert("received".to_owned(), json!([]));
    let mut received = Vec::new();
    while received.len() < 4 {
        let (opcode, payload) = read_client_frame(stream)?;
        if opcode == 0x1 {
            received.push(serde_json::from_slice::<Value>(&payload).expect("client JSON"));
            record.insert("received".to_owned(), Value::Array(received.clone()));
        }
    }
    let mut pongs = Vec::new();
    for reply in script["replies"].as_array().into_iter().flatten() {
        if reply.get("eof").is_some() {
            return Ok(());
        }
        if let Some(hold) = reply.get("hold").and_then(Value::as_f64) {
            thread::sleep(Duration::from_secs_f64(hold));
            return Ok(());
        }
        if reply.get("close_frame").is_some() {
            stream.write_all(&server_frame(0x8, b""))?;
            return Ok(());
        }
        if let Some(ping) = reply.get("ping").and_then(Value::as_str) {
            stream.write_all(&server_frame(0x9, ping.as_bytes()))?;
            let (opcode, payload) = read_client_frame(stream)?;
            pongs.push(json!({
                "opcode": opcode,
                "payload": String::from_utf8_lossy(&payload),
            }));
            record.insert("pongs".to_owned(), Value::Array(pongs.clone()));
            continue;
        }
        if let Some(bytes) = reply.get("text_bytes").and_then(Value::as_str) {
            let bytes = Base64::decode_vec(bytes).expect("text bytes reply");
            stream.write_all(&server_frame(0x1, &bytes))?;
            continue;
        }
        if let Some(text) = reply.get("masked_text").and_then(Value::as_str) {
            let mask = [1_u8, 2, 3, 4];
            let mut frame = vec![0x81, 0x80 | text.len() as u8];
            frame.extend_from_slice(&mask);
            frame.extend(
                text.bytes()
                    .enumerate()
                    .map(|(index, byte)| byte ^ mask[index % 4]),
            );
            stream.write_all(&frame)?;
            continue;
        }
        if let Some(binary) = reply.get("binary").and_then(Value::as_str) {
            let bytes = Base64::decode_vec(binary).expect("binary reply");
            stream.write_all(&server_frame(0x2, &bytes))?;
            continue;
        }
        if reply.get("oversized").is_some() {
            let mut frame = vec![0x81, 127];
            frame.extend_from_slice(&1_000_001_u64.to_be_bytes());
            stream.write_all(&frame)?;
            continue;
        }
        let text = reply
            .get("raw_text")
            .or_else(|| reply.get("text"))
            .and_then(Value::as_str)
            .unwrap_or_default();
        stream.write_all(&server_frame(0x1, text.as_bytes()))?;
    }
    stream.set_read_timeout(Some(Duration::from_millis(500)))?;
    let mut sink = [0_u8; 4096];
    while stream.read(&mut sink).unwrap_or(0) > 0 {}
    Ok(())
}

fn read_exact(stream: &mut UnixStream, length: usize) -> std::io::Result<Vec<u8>> {
    let mut buffer = vec![0_u8; length];
    stream.read_exact(&mut buffer)?;
    Ok(buffer)
}

fn read_client_frame(stream: &mut UnixStream) -> std::io::Result<(u8, Vec<u8>)> {
    let header = read_exact(stream, 2)?;
    let mut length = u64::from(header[1] & 0x7F);
    if length == 126 {
        let bytes = read_exact(stream, 2)?;
        length = u64::from(u16::from_be_bytes([bytes[0], bytes[1]]));
    } else if length == 127 {
        let bytes = read_exact(stream, 8)?;
        length = u64::from_be_bytes(bytes.try_into().expect("eight bytes"));
    }
    let mask = read_exact(stream, 4)?;
    let mut payload = read_exact(stream, length as usize)?;
    for (index, byte) in payload.iter_mut().enumerate() {
        *byte ^= mask[index % 4];
    }
    Ok((header[0] & 0x0F, payload))
}

fn server_frame(opcode: u8, payload: &[u8]) -> Vec<u8> {
    let mut frame = vec![0x80 | opcode];
    match payload.len() {
        length @ 0..=125 => frame.push(length as u8),
        length @ 126..=65_535 => {
            frame.push(126);
            frame.extend_from_slice(&(length as u16).to_be_bytes());
        }
        length => {
            frame.push(127);
            frame.extend_from_slice(&(length as u64).to_be_bytes());
        }
    }
    frame.extend_from_slice(payload);
    frame
}
