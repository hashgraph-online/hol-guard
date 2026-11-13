//! The sink asks the daemon for the receipt when no resident answers.

use std::io::BufReader;
use std::net::TcpListener;
use std::path::PathBuf;
use std::thread::JoinHandle;
use std::time::Duration;

use serde_json::{json, Map, Value};

use super::super::{Arguments, Authority};
use crate::claude_hook_bridge_fixture::{
    read_request, write_private, write_response, GuardHome, Request,
};

const TOKEN: &str = "sink-token-fixture";

fn serve_once(listener: TcpListener, status: u16, body: String) -> JoinHandle<Option<Request>> {
    std::thread::spawn(move || {
        let (stream, _) = listener.accept().ok()?;
        stream
            .set_read_timeout(Some(Duration::from_secs(10)))
            .unwrap();
        let mut writer = stream.try_clone().unwrap();
        let request = read_request(&mut BufReader::new(stream))?;
        write_response(&mut writer, status, &body, true);
        Some(request)
    })
}

fn home_with_daemon(label: &str, port: u16) -> GuardHome {
    let home = GuardHome::new(label);
    write_private(
        &home.state_path,
        &json!({"host": "127.0.0.1", "port": port}).to_string(),
    );
    write_private(&home.home.join("daemon-auth-token"), TOKEN);
    home
}

fn arguments(guard: &GuardHome) -> Arguments {
    Arguments {
        harness: "omp".to_owned(),
        guard_home: guard.home.clone(),
        workspace: PathBuf::from("/tmp"),
        request_file: PathBuf::from("/tmp/request.json"),
        request_sha256: String::new(),
        home: PathBuf::from("/tmp"),
    }
}

fn payload() -> Map<String, Value> {
    let Value::Object(payload) = json!({
        "hook_event_name": "PreToolUse",
        "tool_name": "bash",
        "tool_call_id": "call_fixture",
        "tool_input": {"command": "python -m pytest tests"},
    }) else {
        unreachable!()
    };
    payload
}

#[test]
fn a_receipt_no_resident_answers_comes_from_the_daemon() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let receipt = json!({"decision": "deny", "policy_action": "sandbox-required"});
    let daemon = serve_once(listener, 200, format!("\u{feff}{receipt}"));
    let guard = home_with_daemon("sink-daemon-receipt", port);
    let arguments = arguments(&guard);
    let authority = Authority {
        arguments: &arguments,
        workspace: "/tmp".to_owned(),
    };

    let answered = authority.authorize(&payload()).unwrap();

    assert_eq!(Value::Object(answered), receipt);
    let request = daemon.join().unwrap().unwrap();
    assert!(request.target.starts_with("/v1/hooks/omp?guard-home="));
    assert!(request.target.contains("&workspace=%2Ftmp&home=%2Ftmp"));
    assert_eq!(request.header("X-Guard-Token"), Some(TOKEN));
    let sent: Value = serde_json::from_slice(&request.body).unwrap();
    assert_eq!(sent["guard_containment_receipt_only"], Value::Bool(true));
    assert_eq!(sent["tool_call_id"], "call_fixture");
}

#[test]
fn a_daemon_refusal_authorizes_nothing() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let receipt = json!({"decision": "deny", "policy_action": "sandbox-required"});
    let daemon = serve_once(listener, 403, receipt.to_string());
    let guard = home_with_daemon("sink-daemon-refusal", port);
    let arguments = arguments(&guard);
    let authority = Authority {
        arguments: &arguments,
        workspace: "/tmp".to_owned(),
    };

    assert!(authority.authorize(&payload()).is_none());
    daemon.join().unwrap().unwrap();
}

#[test]
fn no_daemon_state_authorizes_nothing() {
    let guard = GuardHome::new("sink-daemon-none");
    let arguments = arguments(&guard);
    let authority = Authority {
        arguments: &arguments,
        workspace: "/tmp".to_owned(),
    };

    assert!(authority.authorize(&payload()).is_none());
}
