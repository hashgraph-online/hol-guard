use super::{handle_pending_request, PendingRequest};
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{ErrorKind, Read, Write};
use std::os::unix::fs::PermissionsExt;
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

fn request_bytes(socket: &Path, home: &Path, timeout_ms: u64, thread_id: Option<&str>) -> Vec<u8> {
    let mut metadata = serde_json::Map::new();
    if let Some(thread_id) = thread_id {
        metadata.insert(
            "thread_id".to_owned(),
            serde_json::Value::String(thread_id.to_owned()),
        );
        metadata.insert(
            "codex_app_server_socket".to_owned(),
            serde_json::Value::String(socket.display().to_string()),
        );
    }
    serde_json::to_vec(&serde_json::json!({
        "operation": "codex_thread_continue",
        "request": {
            "schema": "guard-codex-thread-continue-request.v1",
            "request_id": "continuation",
            "approval_request_id": "approval",
            "action": "allow",
            "metadata": metadata,
            "home_dir": home.display().to_string(),
            "timeout_ms": timeout_ms,
        }
    }))
    .unwrap()
}

fn submit(body: &[u8]) -> (UnixStream, PendingRequest) {
    let (mut client, server) = UnixStream::pair().unwrap();
    client.write_all(body).unwrap();
    let digest = Sha256::digest(body);
    let mut request_digest = [0u8; crate::FRAME_DIGEST_BYTES];
    request_digest.copy_from_slice(&digest);
    let pending = PendingRequest {
        peer_identity: None,
        stream: Box::new(server),
        request_id: [9u8; crate::FRAME_REQUEST_ID_BYTES],
        request_digest,
        length: body.len(),
        payload_prefix: Vec::new(),
        accepted_at: Instant::now(),
    };
    (client, pending)
}

fn read_exact_until(
    stream: &mut UnixStream,
    buf: &mut [u8],
    deadline: Instant,
) -> Result<(), String> {
    let mut filled = 0;
    while filled < buf.len() {
        match stream.read(&mut buf[filled..]) {
            Ok(0) => return Err("eof".to_owned()),
            Ok(count) => filled += count,
            Err(error)
                if error.kind() == ErrorKind::WouldBlock
                    || error.kind() == ErrorKind::Interrupted =>
            {
                if Instant::now() >= deadline {
                    return Err("timeout".to_owned());
                }
                thread::sleep(Duration::from_millis(5));
            }
            Err(error) => return Err(format!("read:{error}")),
        }
    }
    Ok(())
}

fn read_body(stream: &mut UnixStream, timeout: Duration) -> Result<Vec<u8>, String> {
    stream
        .set_nonblocking(true)
        .map_err(|error| format!("nonblocking:{error}"))?;
    let deadline = Instant::now() + timeout;
    let mut header = [0u8; crate::FRAME_HEADER_BYTES];
    read_exact_until(stream, &mut header, deadline)?;
    if &header[..4] != crate::RESPONSE_MAGIC {
        return Err(format!("magic:{header:?}"));
    }
    let length = u32::from_be_bytes(header[crate::FRAME_HEADER_BYTES - 4..].try_into().unwrap());
    let mut body = vec![0u8; length as usize];
    read_exact_until(stream, &mut body, deadline)?;
    Ok(body)
}

fn trusted_socket() -> (PathBuf, PathBuf, thread::JoinHandle<()>, Arc<AtomicBool>) {
    let directory = PathBuf::from(format!("/tmp/hgct{}", std::process::id()));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir(&directory).unwrap();
    fs::set_permissions(&directory, fs::Permissions::from_mode(0o700)).unwrap();
    let socket_path = directory.join("s.sock");
    let listener = UnixListener::bind(&socket_path).unwrap();
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600)).unwrap();
    let stop = Arc::new(AtomicBool::new(false));
    let running = Arc::clone(&stop);
    let acceptor = thread::spawn(move || {
        listener.set_nonblocking(true).unwrap();
        let mut held = Vec::new();
        while !running.load(Ordering::Relaxed) && held.len() < 2 {
            match listener.accept() {
                Ok((stream, _)) => held.push(stream),
                Err(error) if error.kind() == ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(5));
                }
                Err(_) => break,
            }
        }
        while !running.load(Ordering::Relaxed) {
            thread::sleep(Duration::from_millis(10));
        }
        drop(held);
    });
    let home = fs::canonicalize(&directory).unwrap();
    let socket = fs::canonicalize(&socket_path).unwrap();
    (home, socket, acceptor, stop)
}

#[test]
fn continuation_io_leaves_the_evaluation_worker() {
    let (home, socket, acceptor, stop) = trusted_socket();
    let stall = request_bytes(&socket, &home, 800, Some("thread1"));
    let (mut first_client, first) = submit(&stall);
    let started = Instant::now();
    handle_pending_request(first, None);
    assert!(
        started.elapsed() < Duration::from_millis(400),
        "continuation stayed on the evaluation worker"
    );
    let early = read_body(&mut first_client, Duration::from_millis(30));
    assert!(
        early.is_err(),
        "response arrived before the continuation could block: {early:?}"
    );

    let (mut second_client, second) = submit(&stall);
    let started = Instant::now();
    handle_pending_request(second, None);
    assert!(started.elapsed() < Duration::from_millis(400));

    let (mut third_client, third) = submit(&stall);
    handle_pending_request(third, None);
    let overload = read_body(&mut third_client, Duration::from_millis(300)).expect("overload");
    let overload_text = String::from_utf8(overload).unwrap();
    assert!(
        overload_text.contains("\"error\":\"native_overloaded\""),
        "{overload_text}"
    );

    for client in [&mut first_client, &mut second_client] {
        let body = read_body(client, Duration::from_secs(2)).expect("continuation result");
        let text = String::from_utf8(body).unwrap();
        assert!(
            text.contains("guard-codex-thread-continue-result.v1"),
            "{text}"
        );
        assert!(!text.contains("native_overloaded"), "{text}");
    }

    let released = request_bytes(&socket, &home, 50, None);
    let (mut released_client, released_pending) = submit(&released);
    handle_pending_request(released_pending, None);
    let released_body =
        read_body(&mut released_client, Duration::from_millis(500)).expect("slot released");
    let released_text = String::from_utf8(released_body).unwrap();
    assert!(
        released_text.contains("guard-codex-thread-continue-result.v1"),
        "{released_text}"
    );
    assert!(
        !released_text.contains("native_overloaded"),
        "{released_text}"
    );

    stop.store(true, Ordering::Relaxed);
    let _ = acceptor.join();
    let _ = fs::remove_dir_all(home);
}
