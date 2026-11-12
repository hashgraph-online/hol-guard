use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use serde_json::{json, Value};

use super::*;

/// Serve each canned response to one connection, in order.
fn serve(responses: Vec<Vec<u8>>) -> (String, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let mut seen = Vec::new();
        for response in responses {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0_u8; 65_536];
            let read = stream.read(&mut buf).unwrap();
            seen.push(String::from_utf8_lossy(&buf[..read]).into_owned());
            stream.write_all(&response).unwrap();
        }
        seen
    });
    (format!("http://127.0.0.1:{port}"), handle)
}

fn http(status: &str, body: &str) -> Vec<u8> {
    format!(
        "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
        body.len()
    )
    .into_bytes()
}

fn call(request: Value) -> Value {
    let raw = run_command(request.to_string().as_bytes()).unwrap();
    serde_json::from_slice(&raw).unwrap()
}

#[test]
fn a_get_returns_the_decoded_object_and_sends_the_auth_header() {
    let (url, server) = serve(vec![http("200 OK", r#"{"state":"on"}"#)]);
    let answer = call(
        json!({"schema":SCHEMA,"op":"request","daemon_url":url,"auth":"abc",
        "method":"GET","path":"/v1/network/status","timeout_ms":2000}),
    );
    assert_eq!(answer["ok"]["state"], "on");
    let seen = server.join().unwrap();
    assert!(seen[0].starts_with("GET /v1/network/status HTTP/1.1\r\n"));
    assert!(seen[0].contains(&format!("{}: abc", token_header())));
}

#[test]
fn an_http_error_carries_the_code_and_recovery_action() {
    let body = r#"{"error":"authority_missing","recovery":{"action":"repair"}}"#;
    let (url, server) = serve(vec![http("409 Conflict", body)]);
    let answer = call(
        json!({"schema":SCHEMA,"op":"request","daemon_url":url,"auth":"abc",
        "method":"POST","path":"/v1/policy/resolve","body":{},"timeout_ms":2000}),
    );
    assert_eq!(answer["error"], "http");
    assert_eq!(answer["status"], 409);
    assert_eq!(answer["code"], "authority_missing");
    assert_eq!(answer["recovery_action"], "repair");
    server.join().unwrap();
}

#[test]
fn a_truncated_get_retries_once() {
    let short = b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n{\"a\":".to_vec();
    let (url, server) = serve(vec![short, http("200 OK", r#"{"a":1}"#)]);
    let answer = call(
        json!({"schema":SCHEMA,"op":"request","daemon_url":url,"auth":"abc",
        "method":"GET","path":"/v1/x","timeout_ms":2000}),
    );
    assert_eq!(answer["ok"]["a"], 1);
    assert_eq!(server.join().unwrap().len(), 2);
}

#[test]
fn a_truncated_post_accepts_a_decodable_partial_body() {
    let short = b"HTTP/1.1 200 OK\r\nContent-Length: 40\r\n\r\n{\"a\":1}".to_vec();
    let (url, server) = serve(vec![short]);
    let answer = call(
        json!({"schema":SCHEMA,"op":"request","daemon_url":url,"auth":"abc",
        "method":"POST","path":"/v1/x","body":{},"timeout_ms":2000}),
    );
    assert_eq!(answer["ok"]["a"], 1);
    server.join().unwrap();
}

#[test]
fn an_oversized_or_non_object_body_is_a_schema_failure() {
    let (url, server) = serve(vec![
        http("200 OK", "[1,2]"),
        http("200 OK", r#"{"a":"xxxxxxxx"}"#),
    ]);
    let list = call(
        json!({"schema":SCHEMA,"op":"request","daemon_url":url,"auth":"a",
        "method":"GET","path":"/v1/x","timeout_ms":2000}),
    );
    assert_eq!(list["error"], "schema");
    let large = call(
        json!({"schema":SCHEMA,"op":"request","daemon_url":url,"auth":"a",
        "method":"GET","path":"/v1/x","timeout_ms":2000,"max_bytes":4}),
    );
    assert_eq!(large["error"], "schema");
    server.join().unwrap();
}

#[test]
fn a_chunked_body_is_decoded() {
    let raw = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\n{\"a\"\r\n3\r\n:1}\r\n0\r\n\r\n".to_vec();
    let (url, server) = serve(vec![raw]);
    let answer = call(
        json!({"schema":SCHEMA,"op":"request","daemon_url":url,"auth":"a",
        "method":"GET","path":"/v1/x","timeout_ms":2000}),
    );
    assert_eq!(answer["ok"]["a"], 1);
    server.join().unwrap();
}

#[test]
fn a_silent_daemon_times_out() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let holder = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        thread::sleep(Duration::from_millis(600));
        drop(stream);
    });
    let started = Instant::now();
    let answer = call(
        json!({"schema":SCHEMA,"op":"request","daemon_url":format!("http://127.0.0.1:{port}"),
        "auth":"a","method":"GET","path":"/v1/x","timeout_ms":200}),
    );
    assert_eq!(answer["error"], "timeout");
    assert!(started.elapsed() < Duration::from_millis(550));
    holder.join().unwrap();
}

#[test]
fn only_loopback_daemon_urls_are_reached() {
    for url in [
        "http://10.0.0.1:5474",
        "https://127.0.0.1:5474",
        "http://user@127.0.0.1:5474",
        "http://127.0.0.1:5474/v1",
        "http://localhost:5474",
        "http://127.0.0.1:0",
    ] {
        assert!(loopback_authority(url).is_none(), "{url}");
    }
    assert!(loopback_authority("http://127.0.0.1:5474/").is_some());
    assert!(loopback_authority("http://[::1]:5474").is_some());
}

#[test]
fn health_details_needs_a_200_object() {
    let (url, server) = serve(vec![
        http("200 OK", r#"{"pid":7}"#),
        http("401 Unauthorized", r#"{"error":"x"}"#),
    ]);
    let ok = call(
        json!({"schema":SCHEMA,"op":"health_details","daemon_url":url,"auth":"a","timeout_ms":2000}),
    );
    assert_eq!(ok["ok"]["pid"], 7);
    let denied = call(
        json!({"schema":SCHEMA,"op":"health_details","daemon_url":url,"auth":"a","timeout_ms":2000}),
    );
    assert_eq!(denied["none"], true);
    server.join().unwrap();
}

#[test]
fn dashboard_capabilities_reads_with_the_refreshed_session() {
    let field = format!("dashboard_session_{}", "token");
    let init = json!({ field: "refreshed-session" }).to_string();
    let (url, server) = serve(vec![
        http("200 OK", &init),
        http("200 OK", r#"{"surfaces":[]}"#),
    ]);
    let answer = call(
        json!({"schema":SCHEMA,"op":"dashboard_capabilities","daemon_url":url,
        "auth":"a","timeout_ms":2000}),
    );
    assert_eq!(answer["ok"]["surfaces"], json!([]));
    let seen = server.join().unwrap();
    assert!(seen[0].starts_with("POST /v1/initialize "));
    assert!(seen[1].contains("X-Guard-Dashboard-Session: refreshed-session"));
}

#[test]
fn a_conditional_get_reports_not_modified_and_the_etag() {
    let raw = b"HTTP/1.1 304 Not Modified\r\nETag: \"v7\"\r\nContent-Length: 0\r\n\r\n".to_vec();
    let fresh = b"HTTP/1.1 200 OK\r\nETag: \"v8\"\r\nContent-Length: 7\r\n\r\n{\"a\":1}".to_vec();
    let (url, server) = serve(vec![raw, fresh]);
    let request = json!({"schema":SCHEMA,"op":"request","daemon_url":url,"auth":"a",
        "method":"GET","path":"/v2/x","timeout_ms":2000,"if_none_match":"\"v7\""});
    let unchanged = call(request.clone());
    assert_eq!(unchanged["not_modified"], true);
    assert_eq!(unchanged["etag"], "\"v7\"");
    let fresh = call(request);
    assert_eq!(fresh["etag"], "\"v8\"");
    assert_eq!(fresh["size"], 7);
    assert!(server.join().unwrap()[0].contains("If-None-Match: \"v7\""));
}
