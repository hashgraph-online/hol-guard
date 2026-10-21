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

/// `guard.db` under `home` with one resolved Codex approval per id, each
/// pending a resume whose operation points at `socket`.
fn seed_store(home: &Path, socket: &Path, approval_ids: &[&str]) {
    let connection = rusqlite::Connection::open(home.join("guard.db")).unwrap();
    connection
        .execute_batch(
            "create table approval_requests (request_id text primary key, harness, resolution_action);
             create table guard_operations (
               operation_id text primary key, session_id text not null, harness text not null,
               operation_type text not null, status text not null,
               approval_request_ids_json text not null, resume_token text,
               metadata_json text not null, created_at text not null, updated_at text not null);
             create table guard_request_resumes (
               request_id text primary key, operation_id text, harness text not null,
               resolution_action text, strategy text not null,
               supported integer not null default 0, status text not null, thread_id text,
               reason text, message text, last_error text,
               attempt_count integer not null default 0, created_at text not null,
               updated_at text not null, last_attempt_at text, sent_at text,
               continuation_contract_version text, continuation_capability text,
               continuation_status text, continuation_reason text,
               continuation_evidence_json text not null default '[]',
               continuation_offer_hash text, continuation_action text,
               continuation_completed_at text, continuation_cancelled_at text);",
        )
        .unwrap();
    let metadata = serde_json::json!({
        "codex_thread_id": "thread1",
        "codex_app_server_socket": socket.display().to_string(),
    })
    .to_string();
    for id in approval_ids {
        connection
            .execute(
                "insert into approval_requests values (?, 'codex', 'allow')",
                [id],
            )
            .unwrap();
        connection
            .execute(
                "insert into guard_operations values (?, 's', 'codex', 'tool', 'waiting', ?, null, ?, 't', 't')",
                rusqlite::params![format!("op-{id}"), serde_json::json!([id]).to_string(), metadata],
            )
            .unwrap();
        connection
            .execute(
                "insert into guard_request_resumes (request_id, harness, strategy, supported, status,
                   thread_id, created_at, updated_at)
                 values (?, 'codex', 'codex-app-server-thread', 1, 'pending', 'thread1', 't', 't')",
                [id],
            )
            .unwrap();
    }
}

fn retry_bytes(home: &Path, approval_id: &str, timeout_ms: u64) -> Vec<u8> {
    serde_json::to_vec(&serde_json::json!({
        "operation": "codex_request_resume",
        "request": {
            "schema": "guard-codex-request-resume-request.v1",
            "request_id": "continuation",
            "approval_request_id": approval_id,
            "call": "retry",
            "now": "2026-10-11T12:00:00+00:00",
            "store_path": home.join("guard.db").display().to_string(),
            "guard_home": home.display().to_string(),
            "busy_timeout_ms": 1000,
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
    seed_store(&home, &socket, &["approval1", "approval2"]);
    let (mut first_client, first) = submit(&retry_bytes(&home, "approval1", 800));
    let started = Instant::now();
    handle_pending_request(first, None, None);
    assert!(
        started.elapsed() < Duration::from_millis(400),
        "continuation stayed on the evaluation worker"
    );
    let early = read_body(&mut first_client, Duration::from_millis(30));
    assert!(
        early.is_err(),
        "response arrived before the continuation could block: {early:?}"
    );

    let (mut second_client, second) = submit(&retry_bytes(&home, "approval2", 800));
    let started = Instant::now();
    handle_pending_request(second, None, None);
    assert!(started.elapsed() < Duration::from_millis(400));

    let (mut third_client, third) = submit(&retry_bytes(&home, "approval1", 800));
    handle_pending_request(third, None, None);
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
            text.contains("guard-codex-request-resume-result.v1"),
            "{text}"
        );
        assert!(!text.contains("native_overloaded"), "{text}");
    }

    let released = retry_bytes(&home, "missing", 50);
    let (mut released_client, released_pending) = submit(&released);
    handle_pending_request(released_pending, None, None);
    let released_body =
        read_body(&mut released_client, Duration::from_millis(500)).expect("slot released");
    let released_text = String::from_utf8(released_body).unwrap();
    assert!(
        released_text.contains("guard-codex-request-resume-result.v1"),
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
