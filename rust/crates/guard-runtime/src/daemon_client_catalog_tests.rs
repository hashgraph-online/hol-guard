use std::io::{Read, Write};
use std::net::TcpListener;
use std::thread;

use serde_json::{json, Value};

use super::super::{run_command, SCHEMA};
use super::{form_encode, percent_encode};

/// Serve each canned JSON body (status, body) to one connection, in order,
/// with an ETag so the client accepts it as a catalog representation.
fn serve(responses: Vec<(u16, Value)>) -> (String, thread::JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let handle = thread::spawn(move || {
        let mut seen = Vec::new();
        for (status, body) in responses {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0_u8; 65_536];
            let read = stream.read(&mut buf).unwrap();
            seen.push(String::from_utf8_lossy(&buf[..read]).into_owned());
            let body = body.to_string();
            let raw = format!(
                "HTTP/1.1 {status} X\r\nETag: \"e\"\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(raw.as_bytes()).unwrap();
        }
        seen
    });
    (format!("http://127.0.0.1:{port}"), handle)
}

fn call(url: &str, op: &str, extra: Value) -> Value {
    let mut request =
        json!({"schema": SCHEMA, "op": op, "daemon_url": url, "auth": "a", "timeout_ms": 3000});
    for (key, value) in extra.as_object().unwrap() {
        request[key] = value.clone();
    }
    let raw = run_command(request.to_string().as_bytes()).unwrap();
    serde_json::from_slice(&raw).unwrap()
}

fn page(items: Value, next: Value, snapshot: &str, total: i64) -> (u16, Value) {
    (
        200,
        json!({"snapshot_id": snapshot, "native_catalog_digest": "d", "total_count": total,
               "items": items, "next_cursor": next}),
    )
}

#[test]
fn a_traversal_walks_every_page_with_sorted_queries() {
    let (url, server) = serve(vec![
        page(json!([{"id": "a"}]), json!("c1"), "s", 2),
        page(json!([{"id": "b"}]), Value::Null, "s", 2),
    ]);
    let answer = call(
        &url,
        "catalog_traverse",
        json!({"route": "permissions", "item_key": "id", "params": {"q": "git push"}}),
    );
    assert_eq!(answer["ok"]["total_count"], 2);
    assert_eq!(answer["ok"]["items"], json!([{"id": "a"}, {"id": "b"}]));
    let seen = server.join().unwrap();
    assert!(seen[0].starts_with(
        "GET /v2/extension-controls/catalog/permissions?limit=100&q=git+push HTTP/1.1"
    ));
    assert!(seen[1].contains("?cursor=c1&limit=100&q=git+push "));
}

#[test]
fn a_changed_snapshot_restarts_the_traversal_once() {
    let (url, server) = serve(vec![
        page(json!([{"id": "a"}]), json!("c1"), "s1", 2),
        page(json!([{"id": "b"}]), Value::Null, "s2", 2),
        page(json!([{"id": "a"}, {"id": "b"}]), Value::Null, "s2", 2),
    ]);
    let answer = call(
        &url,
        "catalog_traverse",
        json!({"route": "index", "item_key": "id"}),
    );
    assert_eq!(answer["ok"]["snapshot_id"], "s2");
    assert_eq!(server.join().unwrap().len(), 3);
}

#[test]
fn duplicates_and_short_traversals_fail_verification() {
    let (url, server) = serve(vec![
        page(json!([{"id": "a"}, {"id": "a"}]), Value::Null, "s", 2),
        page(json!([{"id": "a"}]), Value::Null, "s", 2),
    ]);
    let duplicate = call(
        &url,
        "catalog_traverse",
        json!({"route": "index", "item_key": "id"}),
    );
    assert_eq!(duplicate["error"], "traversal");
    let short = call(
        &url,
        "catalog_traverse",
        json!({"route": "index", "item_key": "id"}),
    );
    assert_eq!(short["error"], "traversal");
    server.join().unwrap();
}

#[test]
fn a_daemon_without_the_read_model_is_unsupported() {
    let (url, server) = serve(vec![
        (404, json!({})),
        (501, json!({"error": "catalog_read_model_unavailable"})),
        (404, json!({"error": "catalog_extension_not_found"})),
    ]);
    for _ in 0..2 {
        let answer = call(&url, "catalog_get", json!({"route": "index"}));
        assert_eq!(answer["error"], "unsupported");
    }
    let missing = call(&url, "catalog_get", json!({"route": "extensions/x"}));
    assert_eq!(missing["error"], "http");
    assert_eq!(missing["code"], "catalog_extension_not_found");
    server.join().unwrap();
}

#[test]
fn an_extension_is_assembled_in_the_v1_shape() {
    let detail = json!({
        "snapshot_id": "s", "native_catalog_digest": "d",
        "extension": {"extension_id": "git tools", "name": "Git", "content_revision": 3,
                      "catalog_defaults": {"enabled": true, "activation": "auto"}},
        "collections": {"permissions": {"total_count": 1}, "rules": {"total_count": 0}},
    });
    let (url, server) = serve(vec![
        (200, detail),
        page(json!([{"permission_id": "p"}]), Value::Null, "s", 1),
        page(json!([]), Value::Null, "s", 0),
    ]);
    let answer = call(
        &url,
        "catalog_extension",
        json!({"extension_id": "git tools"}),
    );
    let extension = &answer["ok"];
    assert_eq!(extension["enabled"], true);
    assert_eq!(extension["activation"], "auto");
    assert!(extension.get("content_revision").is_none());
    assert_eq!(extension["permissions"], json!([{"permission_id": "p"}]));
    assert_eq!(extension["rules"], json!([]));
    let seen = server.join().unwrap();
    assert!(seen[0].starts_with("GET /v2/extension-controls/catalog/extensions/git%20tools "));
}

#[test]
fn encoding_matches_python_quote_plus() {
    assert_eq!(percent_encode("a b/c~", true), "a+b%2Fc~");
    assert_eq!(percent_encode("a b/c", false), "a%20b%2Fc");
    let pairs = vec![("k".to_owned(), "é".to_owned())];
    assert_eq!(form_encode(&pairs), "k=%C3%A9");
}
