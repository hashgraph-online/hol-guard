use super::*;
use serde_json::json;
use std::sync::Mutex as TestMutex;

// Serialize tests that touch the shared SESSIONS registry.
static LOCK: TestMutex<()> = TestMutex::new(());

fn decode(bytes: Vec<u8>) -> Value {
    serde_json::from_slice(&bytes).expect("result json")
}

fn open_req(id: &str, argv: Vec<&str>) -> McpStdioSessionOpenRequestV1 {
    McpStdioSessionOpenRequestV1 {
        schema: guard_contracts::MCP_STDIO_SESSION_OPEN_REQUEST_SCHEMA.to_owned(),
        session_id: id.to_owned(),
        argv: argv.iter().map(|s| s.to_string()).collect(),
        owner_pid: std::process::id(),
        extra_env: None,
        home_dir: None,
        cwd: None,
    }
}

fn close(id: &str) {
    let _ = session_close(&McpStdioSessionCloseRequestV1 {
        schema: guard_contracts::MCP_STDIO_SESSION_IO_REQUEST_SCHEMA.to_owned(),
        session_id: id.to_owned(),
    });
}

#[test]
fn open_rejects_empty_and_overlong_session_id() {
    let _g = LOCK.lock().unwrap();
    for bad in ["", &"x".repeat(200)] {
        let r = decode(session_open(&open_req(bad, vec!["/bin/cat"])).unwrap());
        assert_eq!(r["status"], "error");
        assert_eq!(r["payload"], "invalid_mcp_session_id");
    }
}

#[test]
fn send_recv_close_unknown_session_is_terminal() {
    let _g = LOCK.lock().unwrap();
    let send = session_send(&McpStdioSessionSendRequestV1 {
        schema: guard_contracts::MCP_STDIO_SESSION_IO_REQUEST_SCHEMA.to_owned(),
        session_id: "nope".into(),
        message: json!({"jsonrpc":"2.0","id":1,"result":{}}),
        exchange: None,
    })
    .unwrap();
    assert_eq!(decode(send)["payload"], "mcp_session_not_found");
}

#[test]
fn duplicate_open_is_rejected() {
    let _g = LOCK.lock().unwrap();
    let id = "dup-sess";
    let _ = session_open(&open_req(id, vec!["/bin/cat"]));
    let second = decode(session_open(&open_req(id, vec!["/bin/cat"])).unwrap());
    assert_eq!(second["status"], "error");
    assert_eq!(second["payload"], "mcp_session_exists");
    close(id);
}

#[test]
fn open_send_recv_close_roundtrip_via_cat_echo() {
    let _g = LOCK.lock().unwrap();
    let id = "echo-sess";
    let opened = decode(session_open(&open_req(id, vec!["/bin/cat"])).unwrap());
    assert_eq!(opened["status"], "opened", "open failed: {opened:?}");

    // cat echoes our framed line back; a response-shaped frame surfaces
    // as a child_response.
    let frame = json!({"jsonrpc":"2.0","id":7,"result":{"ok":true}});
    let sent = decode(
        session_send(&McpStdioSessionSendRequestV1 {
            schema: guard_contracts::MCP_STDIO_SESSION_IO_REQUEST_SCHEMA.to_owned(),
            session_id: id.into(),
            message: frame.clone(),
            exchange: None,
        })
        .unwrap(),
    );
    assert_eq!(sent["status"], "sent", "send failed: {sent:?}");

    let recv = decode(
        session_recv(&McpStdioSessionRecvRequestV1 {
            schema: guard_contracts::MCP_STDIO_SESSION_IO_REQUEST_SCHEMA.to_owned(),
            session_id: id.into(),
            timeout_ms: Some(5000),
            await_request_id: Some(json!(7)),
            poll_only: false,
        })
        .unwrap(),
    );
    assert_eq!(recv["status"], "event", "recv failed: {recv:?}");
    assert_eq!(recv["event_kind"], "child_response");
    assert_eq!(recv["payload"]["id"], 7);

    let closed = decode(
        session_close(&McpStdioSessionCloseRequestV1 {
            schema: guard_contracts::MCP_STDIO_SESSION_IO_REQUEST_SCHEMA.to_owned(),
            session_id: id.into(),
        })
        .unwrap(),
    );
    assert_eq!(closed["status"], "closed");
}

#[test]
fn recv_times_out_when_child_silent() {
    let _g = LOCK.lock().unwrap();
    let id = "silent-sess";
    // `sleep` emits nothing; recv must return a bounded timeout, not hang.
    let opened = decode(session_open(&open_req(id, vec!["/bin/sleep", "30"])).unwrap());
    assert_eq!(opened["status"], "opened");
    let recv = decode(
        session_recv(&McpStdioSessionRecvRequestV1 {
            schema: guard_contracts::MCP_STDIO_SESSION_IO_REQUEST_SCHEMA.to_owned(),
            session_id: id.into(),
            timeout_ms: Some(150),
            await_request_id: None,
            poll_only: false,
        })
        .unwrap(),
    );
    assert_eq!(recv["status"], "timeout");
    assert_eq!(recv["timed_out"], true);
    close(id);
}
#[test]
fn close_interrupts_a_blocked_send_without_stalling_other_sessions() {
    let _g = LOCK.lock().unwrap();
    let id = "blocked-send";
    assert_eq!(
        decode(session_open(&open_req(id, vec!["/bin/sleep", "30"])).unwrap())["status"],
        "opened"
    );
    let handle = lookup(id).unwrap();
    let sender = std::thread::spawn(move || {
        session_send(&McpStdioSessionSendRequestV1 {
            schema: guard_contracts::MCP_STDIO_SESSION_IO_REQUEST_SCHEMA.to_owned(),
            session_id: id.into(),
            message: json!({"jsonrpc":"2.0", "id":1, "params":"x".repeat(500_000)}),
            exchange: None,
        })
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while handle.state.try_lock().is_ok() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    let started = std::time::Instant::now();
    let other = decode(session_open(&open_req("other-session", vec!["/bin/cat"])).unwrap());
    close(id);
    close("other-session");
    assert_eq!(other["status"], "opened");
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_eq!(decode(sender.join().unwrap().unwrap())["status"], "error");
}

#[test]
fn close_interrupts_a_long_receive() {
    let _g = LOCK.lock().unwrap();
    let id = "blocked-recv";
    assert_eq!(
        decode(session_open(&open_req(id, vec!["/bin/cat"])).unwrap())["status"],
        "opened"
    );
    let handle = lookup(id).unwrap();
    let receiver = std::thread::spawn(move || {
        session_recv(&McpStdioSessionRecvRequestV1 {
            schema: guard_contracts::MCP_STDIO_SESSION_IO_REQUEST_SCHEMA.to_owned(),
            session_id: id.into(),
            timeout_ms: Some(120_000),
            await_request_id: None,
            poll_only: false,
        })
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(2);
    while handle.state.try_lock().is_ok() && std::time::Instant::now() < deadline {
        std::thread::sleep(Duration::from_millis(5));
    }
    let started = std::time::Instant::now();
    close(id);
    assert!(started.elapsed() < Duration::from_secs(2));
    assert_ne!(
        decode(receiver.join().unwrap().unwrap())["status"],
        "timeout"
    );
}

#[test]
fn dead_proxy_reaps_a_still_running_mcp_child() {
    let _g = LOCK.lock().unwrap();
    let mut owner = std::process::Command::new("/bin/sleep")
        .arg("30")
        .spawn()
        .unwrap();
    let mut request = open_req("dead-owner", vec!["/bin/cat"]);
    request.owner_pid = owner.id();
    let opened = decode(session_open(&request).unwrap());
    let handle = lookup("dead-owner").unwrap();
    let child_pid = handle.state.lock().unwrap().child.id();
    owner.kill().unwrap();
    owner.wait().unwrap();
    reap_orphaned_sessions();
    assert_eq!(opened["status"], "opened");
    assert!(lookup("dead-owner").is_err());
    assert!(crate::resident_process_identity::process_is_definitively_gone(child_pid).unwrap());
}

#[test]
fn opening_another_session_preserves_a_live_owners_final_frame() {
    let _g = LOCK.lock().unwrap();
    let id = "final-frame";
    let command =
        "printf '%s\\n' '{\"jsonrpc\":\"2.0\",\"id\":7,\"result\":{\"final\":true}}'; exit 7";
    assert_eq!(
        decode(session_open(&open_req(id, vec!["/bin/sh", "-c", command])).unwrap())["status"],
        "opened"
    );
    std::thread::sleep(Duration::from_millis(60));
    assert_eq!(
        decode(session_open(&open_req("second-owner", vec!["/bin/cat"])).unwrap())["status"],
        "opened"
    );
    reap_orphaned_sessions();
    let request = McpStdioSessionRecvRequestV1 {
        schema: guard_contracts::MCP_STDIO_SESSION_IO_REQUEST_SCHEMA.to_owned(),
        session_id: id.into(),
        timeout_ms: Some(1000),
        await_request_id: None,
        poll_only: false,
    };
    let frame = decode(session_recv(&request).unwrap());
    let exited = decode(session_recv(&request).unwrap());
    close(id);
    close("second-owner");
    assert_eq!(frame["payload"]["result"]["final"], true);
    assert_eq!(exited["status"], "exited");
    assert_eq!(exited["exit_code"], 7);
}

#[test]
fn open_rejects_an_invalid_owner_without_spawning() {
    let _g = LOCK.lock().unwrap();
    let mut request = open_req("invalid-owner", vec!["/bin/cat"]);
    request.owner_pid = 0;
    assert_eq!(
        decode(session_open(&request).unwrap())["payload"],
        "invalid_mcp_session_owner"
    );
    assert!(lookup("invalid-owner").is_err());
}

fn exchange(id: &str, message: Value, quiet_ms: u64, response_timeout_ms: u64) -> Value {
    decode(
        session_send(&McpStdioSessionSendRequestV1 {
            schema: guard_contracts::MCP_STDIO_SESSION_IO_REQUEST_SCHEMA.to_owned(),
            session_id: id.into(),
            message,
            exchange: Some(guard_contracts::McpStdioSessionExchangeV1 {
                quiet_ms,
                response_timeout_ms,
            }),
        })
        .unwrap(),
    )
}

#[test]
fn exchange_writes_after_quiet_and_returns_the_correlated_response() {
    let _g = LOCK.lock().unwrap();
    let id = "exchange-response";
    assert_eq!(
        decode(session_open(&open_req(id, vec!["/bin/cat"])).unwrap())["status"],
        "opened"
    );
    let reply = exchange(
        id,
        json!({"jsonrpc":"2.0","id":7,"result":{"ok":true}}),
        5,
        5000,
    );
    assert_eq!(reply["status"], "sent", "{reply:?}");
    assert_eq!(reply["payload"]["outcome"], "response");
    assert_eq!(reply["payload"]["written"], true);
    assert_eq!(reply["payload"]["frame"]["id"], 7);
    close(id);
}

#[test]
fn exchange_returns_a_frame_seen_during_the_quiet_edge_without_writing() {
    let _g = LOCK.lock().unwrap();
    let id = "exchange-boundary";
    let script =
        r#"printf '%s\n' '{"jsonrpc":"2.0","method":"notifications/tools/list_changed"}'; cat"#;
    assert_eq!(
        decode(session_open(&open_req(id, vec!["/bin/sh", "-c", script])).unwrap())["status"],
        "opened"
    );
    let reply = exchange(id, json!({"jsonrpc":"2.0","id":3,"result":{}}), 2000, 2000);
    assert_eq!(reply["payload"]["outcome"], "boundary", "{reply:?}");
    assert_eq!(reply["payload"]["written"], false);
    assert_eq!(reply["payload"]["event_kind"], "child_notification");
    // Nothing was written, so the echoing child has nothing to return.
    let recv = decode(
        session_recv(&McpStdioSessionRecvRequestV1 {
            schema: guard_contracts::MCP_STDIO_SESSION_IO_REQUEST_SCHEMA.to_owned(),
            session_id: id.into(),
            timeout_ms: Some(100),
            await_request_id: None,
            poll_only: false,
        })
        .unwrap(),
    );
    assert_eq!(recv["status"], "timeout");
    close(id);
}

#[test]
fn exchange_waits_for_a_notification_that_is_still_arriving() {
    let _g = LOCK.lock().unwrap();
    let id = "exchange-partial-boundary";
    // The notification starts before the quiet edge ends and finishes after it.
    let script = r#"printf '%s' '{"jsonrpc":"2.0","method":"notifications/tools/'; sleep 1; printf '%s\n' 'list_changed"}'; cat"#;
    assert_eq!(
        decode(session_open(&open_req(id, vec!["/bin/sh", "-c", script])).unwrap())["status"],
        "opened"
    );
    let reply = exchange(id, json!({"jsonrpc":"2.0","id":3,"result":{}}), 600, 2000);
    assert_eq!(reply["payload"]["outcome"], "boundary", "{reply:?}");
    assert_eq!(reply["payload"]["written"], false);
    assert_eq!(reply["payload"]["event_kind"], "child_notification");
    close(id);
}

#[test]
fn exchange_refuses_when_a_partial_frame_outlives_the_extension() {
    let _g = LOCK.lock().unwrap();
    let id = "exchange-partial-busy";
    // The child starts a notification then holds it open past the one second
    // extension: the quiet edge never becomes genuine silence, so the guarded
    // call must be refused rather than written.
    let script = r#"printf '%s' '{"jsonrpc":"2.0","method":"notifications/tools/'; sleep 3; printf '%s\n' 'list_changed"}'; cat"#;
    assert_eq!(
        decode(session_open(&open_req(id, vec!["/bin/sh", "-c", script])).unwrap())["status"],
        "opened"
    );
    let reply = exchange(id, json!({"jsonrpc":"2.0","id":3,"result":{}}), 200, 2000);
    assert_eq!(reply["status"], "error", "{reply:?}");
    assert_eq!(reply["payload"], "mcp_exchange_quiet_edge_busy");
    close(id);
}

#[test]
fn exchange_times_out_after_writing_when_the_child_stays_silent() {
    let _g = LOCK.lock().unwrap();
    let id = "exchange-timeout";
    assert_eq!(
        decode(session_open(&open_req(id, vec!["/bin/sleep", "30"])).unwrap())["status"],
        "opened"
    );
    let reply = exchange(
        id,
        json!({"jsonrpc":"2.0","id":4,"method":"tools/call"}),
        5,
        100,
    );
    assert_eq!(reply["payload"]["outcome"], "timeout", "{reply:?}");
    assert_eq!(reply["payload"]["written"], true);
    close(id);
}

#[test]
fn exchange_surfaces_a_frame_that_is_not_the_awaited_response() {
    let _g = LOCK.lock().unwrap();
    let id = "exchange-event";
    assert_eq!(
        decode(session_open(&open_req(id, vec!["/bin/cat"])).unwrap())["status"],
        "opened"
    );
    // cat echoes the request back, which is a child request, not the response.
    let reply = exchange(
        id,
        json!({"jsonrpc":"2.0","id":9,"method":"tools/call"}),
        5,
        5000,
    );
    assert_eq!(reply["payload"]["outcome"], "event", "{reply:?}");
    assert_eq!(reply["payload"]["written"], true);
    assert_eq!(reply["payload"]["event_kind"], "child_request");
    close(id);
}

#[test]
fn exchange_without_a_request_id_is_refused_before_any_write() {
    let _g = LOCK.lock().unwrap();
    let id = "exchange-no-id";
    assert_eq!(
        decode(session_open(&open_req(id, vec!["/bin/cat"])).unwrap())["status"],
        "opened"
    );
    let reply = exchange(
        id,
        json!({"jsonrpc":"2.0","method":"notifications/initialized"}),
        5,
        100,
    );
    assert_eq!(reply["status"], "error");
    assert_eq!(reply["payload"], "mcp_exchange_requires_request_id");
    close(id);
}
