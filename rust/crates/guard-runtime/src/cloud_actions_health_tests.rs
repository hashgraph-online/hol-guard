use super::*;

fn ask(request: Value) -> Value {
    answer(request).expect("answer")
}

fn service_check(status: Option<u16>, body: &[u8]) -> Value {
    ask(json!({
        "op": "service",
        "status": status,
        "body": STANDARD.encode(body),
        "resource": "https://cloud.example/mcp",
    }))
}

fn connection_check(status: Option<u16>, body: &[u8]) -> Value {
    ask(json!({"op": "connection", "status": status, "body": STANDARD.encode(body)}))
}

const DESCRIPTION: &[u8] =
    br#"{"resource": "https://cloud.example/mcp", "scopes_supported": ["gateway:invoke"]}"#;

#[test]
fn an_unreachable_cloud_is_offline_without_a_status() {
    let expected = json!({"state": "offline", "message": "Guard Cloud could not be reached."});
    assert_eq!(service_check(None, b""), expected);
    assert_eq!(connection_check(None, b""), expected);
}

#[test]
fn the_service_check_reads_the_public_description() {
    assert_eq!(
        service_check(Some(200), DESCRIPTION),
        json!({"state": "current", "message": "Guard Cloud offers Cloud actions.", "http_status": 200})
    );
    assert_eq!(service_check(Some(404), b"")["state"], "not_turned_on");
    assert_eq!(
        service_check(Some(500), DESCRIPTION)["message"],
        "Guard Cloud answered HTTP 500."
    );
    assert_eq!(
        service_check(Some(200), b"[]")["state"],
        "unexpected_answer"
    );
    let moved =
        br#"{"resource": "https://other.example/mcp", "scopes_supported": ["gateway:invoke"]}"#;
    assert_eq!(service_check(Some(200), moved)["state"], "changed");
    let unlisted =
        br#"{"resource": "https://cloud.example/mcp", "scopes_supported": "gateway:invoke"}"#;
    assert_eq!(
        service_check(Some(200), unlisted)["message"],
        "Guard Cloud did not list the Cloud actions permissions."
    );
    let withdrawn =
        br#"{"resource": "https://cloud.example/mcp", "scopes_supported": ["gateway:read"]}"#;
    assert_eq!(
        service_check(Some(200), withdrawn)["message"],
        "Guard Cloud no longer offers Cloud actions to AI tools."
    );
}

#[test]
fn an_event_stream_reply_is_read_from_its_first_data_line() {
    let stream = b"event: message\r\ndata: {\"jsonrpc\": \"2.0\", \"id\": \"hol-guard-status\", \"result\": {}}\r\ndata: []\r\n";
    assert_eq!(
        connection_check(Some(200), stream),
        json!({
            "state": "connected",
            "message": "Guard Cloud accepted this computer.",
            "http_status": 200,
            "actions": "available",
        })
    );
    let unreadable_first =
        b"data: nope\ndata: {\"jsonrpc\": \"2.0\", \"id\": \"hol-guard-status\", \"result\": {}}\n";
    assert_eq!(
        connection_check(Some(200), unreadable_first)["state"],
        "unexpected_answer"
    );
}

#[test]
fn an_oversized_or_undecodable_reply_is_no_answer() {
    let mut oversized = br#"{"jsonrpc": "2.0", "id": "hol-guard-status", "result": {}}"#.to_vec();
    oversized.resize(MAX_RESPONSE_BYTES + 1, b' ');
    assert_eq!(
        connection_check(Some(200), &oversized)["state"],
        "unexpected_answer"
    );
    assert_eq!(
        connection_check(Some(200), b"\xff\xfe")["state"],
        "unexpected_answer"
    );
    assert_eq!(
        service_check(Some(200), &[b'['; 2000])["state"],
        "unexpected_answer"
    );
}

#[test]
fn method_not_found_means_connected_without_actions() {
    for code in ["-32601", "-32601.0"] {
        let reply = format!(r#"{{"jsonrpc": "2.0", "id": null, "error": {{"code": {code}}}}}"#);
        let check = connection_check(Some(200), reply.as_bytes());
        assert_eq!(check["state"], "connected", "{code}");
        assert_eq!(check["actions"], "not_available_yet");
        assert_eq!(
            connection_check(Some(501), reply.as_bytes())["state"],
            "connected"
        );
    }
    let other_id = br#"{"jsonrpc": "2.0", "id": "other", "error": {"code": -32601}}"#;
    assert_eq!(
        connection_check(Some(200), other_id)["state"],
        "unexpected_answer"
    );
    let wrong_code = br#"{"jsonrpc": "2.0", "error": {"code": -32600}}"#;
    assert_eq!(
        connection_check(Some(501), wrong_code)["state"],
        "unexpected_answer"
    );
}

#[test]
fn a_success_status_alone_is_not_a_ping_reply() {
    for body in [
        &br#"<html>proxy</html>"#[..],
        &br#"{"jsonrpc": "1.0", "id": "hol-guard-status", "result": {}}"#[..],
        &br#"{"jsonrpc": "2.0", "id": "other", "result": {}}"#[..],
    ] {
        assert_eq!(
            connection_check(Some(204), body)["message"],
            "Guard Cloud answered HTTP 204 without a Cloud actions reply."
        );
    }
}

#[test]
fn refusals_name_what_guard_cloud_refused() {
    let state = |status| connection_check(Some(status), b"")["state"].clone();
    assert_eq!(state(401), "reconnect");
    assert_eq!(state(403), "not_permitted");
    assert_eq!(state(400), "workspace_mismatch");
    assert_eq!(state(404), "not_turned_on");
    assert_eq!(state(502), "unexpected_answer");
    assert_eq!(
        connection_check(Some(401), b"")["message"],
        "Guard Cloud no longer accepts this computer. Run hol-guard connect."
    );
}

#[test]
fn a_malformed_request_is_refused() {
    for request in [
        json!({"op": "service", "status": 200, "body": "!!", "resource": "x"}),
        json!({"op": "connection", "status": 200, "body": "", "extra": 1}),
        json!({"op": "ping"}),
    ] {
        assert_eq!(answer(request), Err(invalid()));
    }
    assert_eq!(
        run_command(&b"{"[..]),
        Err("cloud_actions_health_request_invalid".to_owned())
    );
}
