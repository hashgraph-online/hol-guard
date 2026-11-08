use super::super::http::{parse_get, query_int, query_value};
use super::super::serve;
use super::*;
use std::net::{SocketAddr, TcpListener};
use std::sync::mpsc;
use std::thread;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use sha2::Sha256;

const TOKEN: &str = "edge-test-token";

fn handshake(guard_home: &Path) -> Vec<u8> {
    serde_json::to_vec(&json!({
        "schema": HANDSHAKE_SCHEMA,
        "auth_token": TOKEN,
        "guard_home": guard_home.to_str().unwrap(),
        "store_path": guard_home.join("guard.db").to_str().unwrap(),
        "source": "default",
        "busy_timeout_ms": 2000,
        "dashboard_build": "abc123",
    }))
    .unwrap()
}

#[test]
fn reads_a_plain_get_head() {
    let head = b"GET /v1/receipts?limit=5 HTTP/1.1\r\nHost: x\r\nX-Guard-Token:  t \r\n\r\n";
    let request = parse_get(head).unwrap();
    assert_eq!(request.path, "/v1/receipts");
    assert_eq!(request.query, "limit=5");
    // Python's header parser drops leading blanks and keeps trailing ones.
    assert_eq!(request.single_header("x-guard-token"), Some("t "));
    assert!(request.has_header("HOST"));
}

#[test]
fn gives_up_on_heads_it_would_not_read_as_the_daemon_does() {
    for head in [
        &b"POST /v1/receipts HTTP/1.1\r\n\r\n"[..],
        b"GET /v1/receipts HTTP/2\r\n\r\n",
        b"GET //v1/receipts HTTP/1.1\r\n\r\n",
        b"GET /v1/receipts/ HTTP/1.1\r\n\r\n",
        b"GET /v1/receipts/a%2Fb HTTP/1.1\r\n\r\n",
        b"GET /v1/receipts;x HTTP/1.1\r\n\r\n",
        b"GET /v1/receipts#x HTTP/1.1\r\n\r\n",
        b"GET /v1/receipts HTTP/1.1\r\nX-A: 1\r\n folded\r\n\r\n",
        b"GET /v1/receipts HTTP/1.1\r\nX-A: 1\nX-B: 2\r\n\r\n",
        b"GET /v1/receipts HTTP/1.1\r\nNoColon\r\n\r\n",
        b"GET  /v1/receipts HTTP/1.1\r\n\r\n",
    ] {
        assert!(
            parse_get(head).is_none(),
            "{}",
            String::from_utf8_lossy(head)
        );
    }
}

#[test]
fn a_repeated_header_has_no_single_value() {
    let head = b"GET /v1/read-state HTTP/1.1\r\nX-Guard-Token: a\r\nx-guard-token: a\r\n\r\n";
    assert_eq!(
        parse_get(head).unwrap().single_header("X-Guard-Token"),
        None
    );
}

#[test]
fn query_values_decode_as_parse_qs_does() {
    assert_eq!(
        query_value("harness=a&harness=b", "harness"),
        Ok(Some("b".into()))
    );
    assert_eq!(
        query_value("harness=a&harness=", "harness"),
        Ok(Some("a".into()))
    );
    assert_eq!(query_value("harness", "harness"), Ok(None));
    assert_eq!(
        query_value("har%6Eess=a+b%21", "harness"),
        Ok(Some("a b!".into()))
    );
    assert_eq!(query_value("harness=%zz", "harness"), Err(()));
    assert_eq!(query_value("harness=%ff", "harness"), Err(()));
    assert_eq!(query_int("", "limit", 200), Ok(200));
    assert_eq!(query_int("limit=-3", "limit", 200), Ok(-3));
    assert_eq!(query_int("limit=007", "limit", 200), Ok(7));
    for spelling in ["limit=%2B5", "limit=%205", "limit=5_0", "limit=five"] {
        assert_eq!(query_int(spelling, "limit", 200), Err(()), "{spelling}");
    }
}

#[test]
fn takes_only_a_complete_valid_handshake() {
    let home = tempfile::tempdir().unwrap();
    let reads = NativeReads::new(None);
    reads.accept_handshake(b"{\"schema\":\"other\"}");
    assert!(reads.config().is_none());
    let mut relative: Value = serde_json::from_slice(&handshake(home.path())).unwrap();
    relative["guard_home"] = json!("relative");
    reads.accept_handshake(&serde_json::to_vec(&relative).unwrap());
    assert!(reads.config().is_none());
    let mut extra: Value = serde_json::from_slice(&handshake(home.path())).unwrap();
    extra["unexpected"] = json!(true);
    reads.accept_handshake(&serde_json::to_vec(&extra).unwrap());
    assert!(reads.config().is_none());
    reads.accept_handshake(&handshake(home.path()));
    let config = reads.config().unwrap();
    assert_eq!(config.token, TOKEN.as_bytes());
    assert_eq!(config.dashboard_build.as_deref(), Some("abc123"));
}

#[test]
fn responses_are_html_safe_json_with_the_daemon_headers() {
    let response = json_response(200, &json!({"a": "<&>"}), Some("abc123"), None, false);
    let text = String::from_utf8(response).unwrap();
    let (head, body) = text.split_once("\r\n\r\n").unwrap();
    assert!(head.starts_with("HTTP/1.0 200 OK\r\n"));
    assert!(head.contains("\r\nContent-Type: application/json; charset=utf-8\r\n"));
    assert!(head.contains(&format!("\r\nContent-Length: {}\r\n", body.len())));
    assert!(head.contains("\r\nX-Content-Type-Options: nosniff\r\n"));
    assert!(head.contains("\r\nX-Guard-Dashboard-Build: abc123\r\n"));
    assert_eq!(body, "{\"a\":\"\\u003c\\u0026\\u003e\"}");
}

/// A daemon that sends each connection's request bytes back on `requests`
/// and answers `daemon`.
fn spawn_recording_daemon() -> (SocketAddr, mpsc::Receiver<Vec<u8>>) {
    let daemon = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream = daemon.local_addr().unwrap();
    let (sender, requests) = mpsc::channel();
    thread::spawn(move || {
        for connection in daemon.incoming() {
            let mut connection = connection.unwrap();
            let mut request = Vec::new();
            let mut chunk = [0u8; 4096];
            while super::super::http::head_end(&request).is_none() {
                match connection.read(&mut chunk) {
                    Ok(0) | Err(_) => break,
                    Ok(read) => request.extend_from_slice(&chunk[..read]),
                }
            }
            sender.send(request).unwrap();
            let _ = connection.write_all(b"daemon");
        }
    });
    (upstream, requests)
}

struct Edge {
    address: SocketAddr,
    requests: mpsc::Receiver<Vec<u8>>,
    activity: UnixStream,
    _home: tempfile::TempDir,
}

fn spawn_configured_edge() -> Edge {
    let home = tempfile::tempdir().unwrap();
    let guard_home = home.path().canonicalize().unwrap();
    let connection = rusqlite::Connection::open(guard_home.join("guard.db")).unwrap();
    connection
        .execute_batch(
            "create table guard_review_outbox_events (
                 stream_sequence integer primary key autoincrement,
                 payload_hash text not null default ''
             );
             create table guard_request_read_state (request_id text primary key, read_at text not null);
             insert into guard_request_read_state values ('older', 't1'), ('newer', 't2');",
        )
        .unwrap();
    drop(connection);
    let (upstream, requests) = spawn_recording_daemon();
    let (activity, edge_end) = UnixStream::pair().unwrap();
    let reads = Arc::new(NativeReads::new(Some(edge_end)));
    reads.accept_handshake(&handshake(&guard_home));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || serve(&listener, upstream, 8, Duration::from_secs(30), reads));
    Edge {
        address,
        requests,
        activity,
        _home: home,
    }
}

fn exchange(address: SocketAddr, request: &str) -> String {
    let mut client = TcpStream::connect(address).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    client.write_all(request.as_bytes()).unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    response
}

#[test]
fn answers_a_token_read_itself_and_reports_the_activity() {
    let edge = spawn_configured_edge();
    let response = exchange(
        edge.address,
        &format!("GET /v1/read-state HTTP/1.1\r\nHost: x\r\nX-Guard-Token: {TOKEN}\r\n\r\n"),
    );
    assert!(response.starts_with("HTTP/1.0 200 OK\r\n"), "{response}");
    assert!(
        response.ends_with(r#"{"ids":["newer","older"]}"#),
        "{response}"
    );
    assert!(edge.requests.try_recv().is_err());
    edge.activity
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let mut byte = [0u8; 1];
    assert_eq!((&edge.activity).read(&mut byte).unwrap(), 1);

    let response = exchange(
        edge.address,
        &format!(
            "GET /v1/receipts/latest?harness=codex HTTP/1.1\r\nX-Guard-Token: {TOKEN}\r\n\r\n"
        ),
    );
    assert!(
        response.starts_with("HTTP/1.0 400 Bad Request\r\n"),
        "{response}"
    );
    assert!(
        response.ends_with(r#"{"error":"missing_receipt_query"}"#),
        "{response}"
    );
}

#[test]
fn answers_a_dashboard_session_with_the_daemon_cors_headers() {
    let edge = spawn_configured_edge();
    let claims = json!({
        "aud": "guard-local-daemon",
        "surface": "dashboard",
        "expires_at": "2999-01-01T00:00:00+00:00",
    });
    let payload = URL_SAFE_NO_PAD.encode(serde_json::to_vec(&claims).unwrap());
    let mut mac = Hmac::<Sha256>::new_from_slice(TOKEN.as_bytes()).unwrap();
    mac.update(payload.as_bytes());
    let session = format!(
        "gld1.{payload}.{}",
        URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes())
    );
    let response = exchange(
        edge.address,
        &format!(
            "GET /v1/read-state HTTP/1.1\r\nOrigin: http://127.0.0.1:5474\r\nX-Guard-Dashboard-Session: {session}\r\n\r\n"
        ),
    );
    let (head, body) = response.split_once("\r\n\r\n").unwrap();
    assert!(head.starts_with("HTTP/1.0 200 OK\r\n"), "{response}");
    assert!(head.contains("\r\nAccess-Control-Allow-Origin: http://127.0.0.1:5474\r\n"));
    assert!(head.contains("\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\n"));
    assert!(head.contains("\r\nAccess-Control-Allow-Private-Network: true\r\n"));
    assert!(head.contains("\r\nVary: Origin\r\n"));
    assert_eq!(body, r#"{"ids":["newer","older"]}"#);
    assert!(edge.requests.try_recv().is_err());
}

#[test]
fn replays_everything_else_to_the_daemon_byte_for_byte() {
    let edge = spawn_configured_edge();
    for request in [
        "GET /v1/read-state HTTP/1.1\r\nX-Guard-Token: wrong\r\n\r\n".to_owned(),
        "GET /v1/read-state HTTP/1.1\r\n\r\n".to_owned(),
        format!(
            "GET /v1/read-state HTTP/1.1\r\nOrigin: http://x\r\nX-Guard-Token: {TOKEN}\r\n\r\n"
        ),
        "GET /v1/read-state HTTP/1.1\r\nX-Guard-Dashboard-Session: gld1.e30.x\r\n\r\n".to_owned(),
        format!("GET /v1/requests HTTP/1.1\r\nX-Guard-Token: {TOKEN}\r\n\r\n"),
        format!("GET /v1/receipts/analytics HTTP/1.1\r\nX-Guard-Token: {TOKEN}\r\n\r\n"),
        format!("POST /v1/read-state HTTP/1.1\r\nX-Guard-Token: {TOKEN}\r\n\r\n"),
        // The store has no receipts table, so the read fails and the daemon
        // answers it instead.
        format!("GET /v1/receipts HTTP/1.1\r\nX-Guard-Token: {TOKEN}\r\n\r\n"),
    ] {
        assert_eq!(exchange(edge.address, &request), "daemon", "{request}");
        let relayed = edge.requests.recv_timeout(Duration::from_secs(20)).unwrap();
        assert_eq!(relayed, request.as_bytes());
    }
}

#[test]
fn leaves_a_head_still_arriving_to_the_daemon() {
    let edge = spawn_configured_edge();
    let request = format!("GET /v1/read-state HTTP/1.1\r\nX-Guard-Token: {TOKEN}\r\n\r\n");
    let (first, rest) = request.split_at(20);
    let mut client = TcpStream::connect(edge.address).unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(20)))
        .unwrap();
    client.write_all(first.as_bytes()).unwrap();
    thread::sleep(HEAD_PEEK_WINDOW * 8);
    client.write_all(rest.as_bytes()).unwrap();
    let mut response = String::new();
    client.read_to_string(&mut response).unwrap();
    assert_eq!(response, "daemon");
    let relayed = edge.requests.recv_timeout(Duration::from_secs(20)).unwrap();
    assert_eq!(relayed, request.as_bytes());
}
