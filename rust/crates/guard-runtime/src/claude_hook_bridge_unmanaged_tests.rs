//! A daemon's passthrough for an app Guard does not manage is a valid answer
//! on the native Claude hook bridge, not a malformed one.

use std::io::Cursor;

use serde_json::{json, Value};

use crate::claude_hook_bridge::hook_response;
use crate::claude_hook_bridge_fixture::{closed_port, home_with_daemon, Exchange, GuardHome};

const PRE_TOOL_USE: &str =
    r#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"echo ok"}}"#;
const PERMISSION_REQUEST: &str = r#"{"hook_event_name":"PermissionRequest","tool_name":"Bash","tool_input":{"command":"echo ok"}}"#;
const UNMANAGED: &str = r#"{"continue":true,"reason_code":"harness_not_managed"}"#;

fn config_for(home: &GuardHome) -> String {
    json!({
        "state_path": home.state_path.to_str().unwrap(),
        "fallback_daemon_url": format!("http://127.0.0.1:{}", closed_port()),
        "query": format!("guard-home={}", home.home_text().replace('/', "%2F")),
        "fallback_command": ["/bin/sh", "-c", "exit 3"],
        "recovery_command": [],
    })
    .to_string()
}

fn respond(home: &GuardHome, input: &str) -> Value {
    let text = hook_response(
        &config_for(home),
        &mut Cursor::new(input.as_bytes().to_vec()),
    )
    .expect("hook response");
    serde_json::from_str(&text).expect("hook JSON")
}

fn decision(response: &Value) -> &str {
    response["hookSpecificOutput"]["permissionDecision"]
        .as_str()
        .unwrap_or_default()
}

#[test]
fn a_daemon_passthrough_for_an_unmanaged_app_is_not_malformed() {
    for event in [PRE_TOOL_USE, PERMISSION_REQUEST] {
        let (home, daemon) =
            home_with_daemon("unmanaged", vec![Exchange::Hook(200, UNMANAGED.to_owned())]);
        let response = respond(&home, event);
        assert_eq!(response, serde_json::from_str::<Value>(UNMANAGED).unwrap());
        daemon.join().unwrap();
    }
}

#[test]
fn an_unmanaged_passthrough_with_anything_more_is_still_malformed() {
    for body in [
        r#"{"continue":true,"reason_code":"harness_not_managed","extra":1}"#,
        r#"{"continue":false,"reason_code":"harness_not_managed"}"#,
        r#"{"continue":true,"reason_code":"something_else"}"#,
    ] {
        let (home, daemon) = home_with_daemon(
            "unmanaged-extra",
            vec![Exchange::Hook(200, body.to_owned())],
        );
        assert_eq!(decision(&respond(&home, PRE_TOOL_USE)), "deny", "{body}");
        daemon.join().unwrap();
    }
}
