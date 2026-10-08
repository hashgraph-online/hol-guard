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
