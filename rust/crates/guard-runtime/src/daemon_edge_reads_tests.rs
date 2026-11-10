use super::super::http::{parse_get, query_int, query_value};
use super::super::serve;
use super::*;
use std::io::Read;
use std::net::{SocketAddr, TcpListener};
use std::os::unix::net::UnixStream;
use std::sync::mpsc;
use std::thread;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde_json::json;
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
             insert into guard_request_read_state values ('older', 't1'), ('newer', 't2');
             create table guard_evidence (evidence_id text primary key);
             insert into guard_evidence values ('e1'), ('e2');
             create table command_activity (activity_id text primary key);
             insert into command_activity values ('act-1');
             create table command_activity_feedback (
                 activity_id text primary key, label text, created_at text,
                 updated_at text, schema_version text
             );",
        )
        .unwrap();
    drop(connection);
    let (upstream, requests) = spawn_recording_daemon();
    let (activity, edge_end) = UnixStream::pair().unwrap();
    let reads = Arc::new(NativeReads::new(Some(edge_end)));
    reads.accept_handshake(&handshake(&guard_home));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || serve(&listener, Some(upstream), 8, Duration::from_secs(30), reads));
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

fn post(body: &str, extra_headers: &str) -> String {
    format!(
        "POST /v1/read-state HTTP/1.1\r\nX-Guard-Token: {TOKEN}\r\nContent-Type: application/json\r\n{extra_headers}Content-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

#[test]
fn updates_read_state_itself_as_the_daemon_does() {
    let edge = spawn_configured_edge();
    for (body, status, answer) in [
        (
            r#"{"action":"mark_unread","request_id":"older"}"#,
            "200 OK",
            r#"{"ids":["newer"],"ok":true}"#,
        ),
        (
            r#"{"action":"mark_all_read","request_ids":["a",1,"b"]}"#,
            "200 OK",
            r#"{"ids":["a","b","newer"],"ok":true}"#,
        ),
        (
            r#"{"action":"other","request_id":"c"}"#,
            "200 OK",
            r#"{"ids":["a","b","c","newer"],"ok":true}"#,
        ),
        (
            r#"{"action":"mark_all_read"}"#,
            "400 Bad Request",
            r#"{"error":"invalid_request_ids"}"#,
        ),
        (
            r#"{"action":"mark_unread","request_id":1}"#,
            "400 Bad Request",
            r#"{"error":"invalid_request_id"}"#,
        ),
        ("[]", "400 Bad Request", r#"{"error":"invalid_action"}"#),
        ("", "400 Bad Request", r#"{"error":"invalid_action"}"#),
    ] {
        let response = exchange(edge.address, &post(body, ""));
        let (head, answered) = response.split_once("\r\n\r\n").unwrap();
        assert!(
            head.starts_with(&format!("HTTP/1.0 {status}\r\n")),
            "{body}: {response}"
        );
        // Marks made in the same second sort by id once their `read_at` ties.
        let mut answered: Value = serde_json::from_str(answered).unwrap();
        if let Some(ids) = answered.get_mut("ids").and_then(Value::as_array_mut) {
            ids.sort_by(|left, right| left.as_str().cmp(&right.as_str()));
        }
        assert_eq!(
            answered,
            serde_json::from_str::<Value>(answer).unwrap(),
            "{body}"
        );
    }
    assert!(edge.requests.try_recv().is_err());
}

#[test]
fn relays_every_post_it_does_not_read_as_the_daemon_does() {
    let edge = spawn_configured_edge();
    let body = r#"{"request_id":"x"}"#;
    for request in [
        post(body, "").replace(TOKEN, "wrong"),
        post(body, "Origin: http://x\r\n"),
        post(body, "").replace("/v1/read-state", "/v1/policy/clear"),
        format!("{}GET /v1/read-state HTTP/1.1\r\n\r\n", post(body, "")),
        post(body, "").replace(
            &format!("Content-Length: {}", body.len()),
            &format!("Content-Length: {}", MAX_BODY_BYTES + 1),
        ),
    ] {
        assert_eq!(exchange(edge.address, &request), "daemon", "{request}");
        let relayed = edge.requests.recv_timeout(Duration::from_secs(20)).unwrap();
        assert!(request.as_bytes().starts_with(&relayed), "{request}");
    }
}

#[test]
fn reads_every_body_the_daemon_reads() {
    let edge = spawn_configured_edge();
    let body = r#"{"request_id":"x"}"#;
    for (request, status) in [
        (
            post(body, "").replace("application/json", "application/x-www-form-urlencoded"),
            "400",
        ),
        (post(body, "Transfer-Encoding: chunked\r\n"), "400"),
        (
            post("request_id=x", "").replace("application/json", "text/plain"),
            "200",
        ),
        (post(body, "Content-Type: text/plain\r\n"), "200"),
        (post("{", ""), "400"),
    ] {
        let response = exchange(edge.address, &request);
        assert!(
            response.starts_with(&format!("HTTP/1.0 {status}")),
            "{request}: {response}"
        );
    }
}

fn delete(path: &str, body: &str) -> String {
    format!(
        "DELETE {path} HTTP/1.1\r\nX-Guard-Token: {TOKEN}\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
}

#[test]
fn clears_read_state_and_evidence_itself_as_the_daemon_does() {
    let edge = spawn_configured_edge();
    let read_state = |edge: &Edge| {
        let response = exchange(
            edge.address,
            &format!("GET /v1/read-state HTTP/1.1\r\nX-Guard-Token: {TOKEN}\r\n\r\n"),
        );
        response.split_once("\r\n\r\n").unwrap().1.to_owned()
    };
    for (body, ids) in [
        ("", r#"{"ids":["newer","older"]}"#),
        ("[1]", r#"{"ids":["newer","older"]}"#),
        (r#"{"clear_all":0}"#, r#"{"ids":["newer","older"]}"#),
        (
            r#"{"request_id":"older","clear_all":true}"#,
            r#"{"ids":["newer"]}"#,
        ),
        (r#"{"clear_all":"yes"}"#, r#"{"ids":[]}"#),
    ] {
        let response = exchange(edge.address, &delete("/v1/read-state", body));
        assert!(
            response.starts_with("HTTP/1.0 200 OK\r\n"),
            "{body}: {response}"
        );
        assert!(response.ends_with(r#"{"ok":true}"#), "{body}: {response}");
        assert_eq!(read_state(&edge), ids, "{body}");
    }
    let response = exchange(edge.address, &delete("/v1/evidence", ""));
    assert!(response.ends_with(r#"{"deleted":2}"#), "{response}");
    assert!(edge.requests.try_recv().is_err());
}

#[test]
fn answers_every_delete_itself_as_the_daemon_did() {
    let edge = spawn_configured_edge();
    for (request, head, tail) in [
        (
            delete("/v1/read-state", "{}").replace(TOKEN, "wrong"),
            "HTTP/1.0 401 ",
            r#""unauthorized"}"#,
        ),
        (delete("/v1/read-state", "NaN"), "HTTP/1.0 200 ", r#"{"ok":true}"#),
        (
            delete("/v1/command-activity", "{}"),
            "HTTP/1.0 400 ",
            r#"{"confirm":"clear-command-activity","error":"confirmation_required"}"#,
        ),
        (
            delete("/v1/command-activity", "[1]"),
            "HTTP/1.0 400 ",
            r#"{"error":"invalid_request"}"#,
        ),
        (
            format!("DELETE /v1/evidence HTTP/1.1\r\nX-Guard-Token: {TOKEN}\r\nTransfer-Encoding: chunked\r\n\r\n"),
            "HTTP/1.0 200 ",
            "}",
        ),
        (delete("/v1/unknown", ""), "HTTP/1.0 404 ", r#"{"error":"not_found"}"#),
    ] {
        let response = exchange(edge.address, &request);
        assert!(response.starts_with(head), "{request}: {response}");
        assert!(response.ends_with(tail), "{request}: {response}");
    }
    assert!(edge.requests.try_recv().is_err());
    let request = format!(
        "POST /v1/evidence HTTP/1.1\r\nX-Guard-Token: {TOKEN}\r\nContent-Length: 0\r\n\r\n"
    );
    assert_eq!(exchange(edge.address, &request), "daemon");
}

#[test]
fn records_command_activity_feedback_itself_as_the_daemon_does() {
    let edge = spawn_configured_edge();
    let feedback = |body: &str| {
        let request = format!(
            "POST /v1/command-activity/feedback HTTP/1.1\r\nX-Guard-Token: {TOKEN}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
            body.len()
        );
        let response = exchange(edge.address, &request);
        let (head, body) = response.split_once("\r\n\r\n").unwrap();
        let status = head.split(' ').nth(1).unwrap().to_owned();
        (status, serde_json::from_str::<Value>(body).unwrap())
    };
    for (body, error) in [
        (r#"{"activity_id":"act-1"}"#, "invalid_feedback_payload"),
        (r#"{"activity_id":"","label":"x"}"#, "invalid_activity_id"),
        (
            r#"{"activity_id":"act-1","label":"maybe"}"#,
            "invalid_feedback_label",
        ),
    ] {
        assert_eq!(
            feedback(body),
            ("400".to_owned(), json!({ "error": error })),
            "{body}"
        );
    }
    let (status, answer) =
        feedback(r#"{"activity_id":"gone","label":"expected_guard_to_stop_this"}"#);
    assert_eq!(
        (status.as_str(), answer),
        ("404", json!({"error": "activity_not_found"}))
    );
    let (status, answer) =
        feedback(r#"{"activity_id":"act-1","label":"should_not_have_interrupted"}"#);
    assert_eq!(status, "200");
    assert_eq!(answer["schema_version"], "guard.command-activity-api.v1");
    assert_eq!(answer["changed"], true);
    assert_eq!(answer["created_at"], answer["updated_at"]);
    assert!(edge.requests.try_recv().is_err());
}

#[test]
fn answers_unavailable_when_the_daemon_listener_is_gone_and_no_cli_can_replay() {
    let home = tempfile::tempdir().unwrap();
    let guard_home = home.path().canonicalize().unwrap();
    let unused = TcpListener::bind("127.0.0.1:0").unwrap();
    let upstream = unused.local_addr().unwrap();
    drop(unused);
    let reads = Arc::new(NativeReads::new(None));
    reads.accept_handshake(&handshake(&guard_home));
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    thread::spawn(move || serve(&listener, Some(upstream), 8, Duration::from_secs(30), reads));
    let response = exchange(
        address,
        "POST /v1/requests HTTP/1.1\r\nContent-Length: 2\r\n\r\n{}",
    );
    assert!(
        response.starts_with("HTTP/1.0 503 Service Unavailable\r\n"),
        "{response}"
    );
    assert!(response.ends_with("{\"error\": \"daemon_route_unavailable\"}\n"));
}

#[test]
fn refuses_the_legacy_cloud_handoff_itself() {
    let edge = spawn_configured_edge();
    let request = post("{}", "").replace("/v1/read-state", "/v1/apps/codex/cloud/start");
    let answer = exchange(edge.address, &request);
    assert!(
        answer.starts_with("HTTP/1.0 410") || answer.starts_with("HTTP/1.1 410"),
        "{answer}"
    );
    assert!(answer.contains("legacy_cloud_handoff_disabled"), "{answer}");
    let relayed = post("{}", "")
        .replace("/v1/read-state", "/v1/apps/codex/cloud/start")
        .replace(TOKEN, "wrong");
    assert_eq!(exchange(edge.address, &relayed), "daemon");
}

#[test]
fn prepares_a_dashboard_reconnect_itself_or_reports_it_unavailable() {
    let edge = spawn_configured_edge();
    let request = post("{}", "").replace("/v1/read-state", "/v1/update/reconnect/prepare");
    let answer = exchange(edge.address, &request);
    let ok = answer.starts_with("HTTP/1.0 200") || answer.starts_with("HTTP/1.1 200");
    let unavailable = answer.starts_with("HTTP/1.0 503") || answer.starts_with("HTTP/1.1 503");
    assert!(ok || unavailable, "{answer}");
    assert!(answer.contains("no-store"), "{answer}");
    if ok {
        assert!(answer.contains("\"verifier\""), "{answer}");
    } else {
        assert!(
            answer.contains("dashboard_reconnect_identity_unavailable"),
            "{answer}"
        );
    }
}

#[test]
fn update_status_forbids_revalidation() {
    let stored = json_response(200, &json!({"a": 1}), None, None, true);
    let patched = String::from_utf8(max_age_zero(stored)).unwrap();
    assert!(
        patched.contains("Cache-Control: no-store, max-age=0\r\n"),
        "{patched}"
    );
    assert!(patched.ends_with("{\"a\":1}"), "{patched}");
    let plain = json_response(200, &json!({}), None, None, false);
    assert_eq!(max_age_zero(plain.clone()), plain);
}
